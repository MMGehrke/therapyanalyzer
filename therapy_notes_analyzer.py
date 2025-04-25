import re
import pandas as pd
import numpy as np
from collections import defaultdict
from typing import List, Dict, Any, Optional
import json
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from datetime import datetime
import logging
import psycopg2
from psycopg2.extras import DictCursor

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class CoTreatmentFactor:
    category: str
    subcategory: str
    description: str
    frequency: int = 0
    confidence_score: float = 0.0

class MIMICTherapyNotesAnalyzer:
    def __init__(self, db_config: Dict[str, str]):
        # Database configuration
        self.db_config = db_config
        self.conn = None
        self._connect_db()
        
        # MIMIC-specific patterns
        self.objective_patterns = {
            'vitals': r'(heart rate|blood pressure|oxygen saturation|SpO2|HR|BP|O2)',
            'diagnosis': r'(ICD-10|diagnosis|dx|primary diagnosis|secondary diagnosis)',
            'ambulation': r'(ambulation|walking|gait|distance|assistance level)',
            'functional_tasks': r'(transfer|dressing|feeding|ADL|activities of daily living)',
            'cognitive': r'(cognitive|alert|oriented|confused|disoriented)',
            'communication': r'(communication|verbal|comprehension|expressive|receptive)',
            'swallowing': r'(swallowing|dysphagia|oral intake|PO status)',
            # MIMIC-specific patterns
            'mimic_diagnosis': r'(ICD9|ICD10|diagnosis_code|diagnosis_description)',
            'mimic_procedures': r'(procedure_code|procedure_description)',
            'mimic_notes': r'(note_text|note_type|note_category)'
        }
        
        # Subjective variables patterns
        self.subjective_patterns = {
            'scheduling': r'(scheduling|coordinate|waiting|time constraint|appointment)',
            'complexity': r'(complex|multi-system|multiple deficits|significant|challenging)',
            'expertise': r'(expertise|experience|skill|knowledge|proficiency)',
            'co_treatment': r'(co-treatment|joint session|combined|collaborative|team approach)',
            # MIMIC-specific patterns
            'mimic_careunit': r'(careunit|unit_type|location)',
            'mimic_service': r'(service|department|specialty)'
        }
        
        # Initialize storage for findings
        self.factors = defaultdict(list)
        self.co_treatment_mentions = 0
        self.total_notes = 0

    def _connect_db(self):
        """Establish connection to MIMIC database."""
        try:
            self.conn = psycopg2.connect(
                dbname=self.db_config['dbname'],
                user=self.db_config['user'],
                password=self.db_config['password'],
                host=self.db_config['host'],
                port=self.db_config['port']
            )
            logger.info("Connected to MIMIC database")
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise

    def process_notes_from_mimic(self, batch_size: int = 1000) -> Dict[str, Any]:
        """Process notes from MIMIC database in batches."""
        if not self.conn:
            raise ValueError("Database connection not established")
        
        results = []
        offset = 0
        
        while True:
            query = """
                SELECT n.text as note_text, 
                       n.category as note_category,
                       n.charttime as note_time,
                       p.subject_id,
                       p.hadm_id
                FROM mimiciii.noteevents n
                JOIN mimiciii.admissions p ON n.hadm_id = p.hadm_id
                WHERE n.category IN ('Nursing', 'Physician', 'Rehab Services')
                ORDER BY n.charttime
                LIMIT %s OFFSET %s
            """
            
            try:
                with self.conn.cursor(cursor_factory=DictCursor) as cursor:
                    cursor.execute(query, (batch_size, offset))
                    rows = cursor.fetchall()
                    
                    if not rows:
                        break
                    
                    # Convert to DataFrame for easier processing
                    df = pd.DataFrame(rows)
                    batch_results = self.analyze_notes(df['note_text'].tolist())
                    results.append(batch_results)
                    
                    offset += batch_size
                    logger.info(f"Processed {offset} notes")
                    
            except Exception as e:
                logger.error(f"Error processing batch: {e}")
                break
        
        return self._combine_batch_results(results)

    def _combine_batch_results(self, batch_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Combine results from multiple batches."""
        combined = {
            'total_notes': sum(r['total_notes'] for r in batch_results),
            'co_treatment_mentions': sum(r['co_treatment_mentions'] for r in batch_results),
            'objective_factors': defaultdict(int),
            'subjective_factors': defaultdict(int)
        }
        
        for result in batch_results:
            for factor, count in result['objective_factors'].items():
                combined['objective_factors'][factor] += count
            for factor, count in result['subjective_factors'].items():
                combined['subjective_factors'][factor] += count
        
        combined['co_treatment_percentage'] = (
            (combined['co_treatment_mentions'] / combined['total_notes'] * 100)
            if combined['total_notes'] > 0 else 0
        )
        
        return combined

    def process_note(self, note_text: str) -> Dict[str, Any]:
        """Process a single therapy note and extract relevant factors."""
        findings = {
            'objective_factors': [],
            'subjective_factors': [],
            'co_treatment_mentioned': False
        }
        
        # Check for co-treatment mentions
        if re.search(self.subjective_patterns['co_treatment'], note_text, re.IGNORECASE):
            findings['co_treatment_mentioned'] = True
            self.co_treatment_mentions += 1
        
        # Extract objective factors
        for category, pattern in self.objective_patterns.items():
            matches = re.finditer(pattern, note_text, re.IGNORECASE)
            for match in matches:
                context = self._get_context(note_text, match.start(), match.end())
                findings['objective_factors'].append({
                    'category': category,
                    'match': match.group(),
                    'context': context
                })
        
        # Extract subjective factors
        for category, pattern in self.subjective_patterns.items():
            matches = re.finditer(pattern, note_text, re.IGNORECASE)
            for match in matches:
                context = self._get_context(note_text, match.start(), match.end())
                findings['subjective_factors'].append({
                    'category': category,
                    'match': match.group(),
                    'context': context
                })
        
        return findings

    def _get_context(self, text: str, start: int, end: int, window: int = 100) -> str:
        """Extract context around a match."""
        start = max(0, start - window)
        end = min(len(text), end + window)
        return text[start:end]

    def analyze_notes(self, notes: List[str]) -> Dict[str, Any]:
        """Analyze a collection of therapy notes."""
        self.total_notes = len(notes)
        results = []
        
        for note in notes:
            findings = self.process_note(note)
            results.append(findings)
        
        return self._summarize_results(results)

    def _summarize_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize the analysis results."""
        summary = {
            'total_notes': self.total_notes,
            'co_treatment_mentions': self.co_treatment_mentions,
            'co_treatment_percentage': (self.co_treatment_mentions / self.total_notes * 100) if self.total_notes > 0 else 0,
            'objective_factors': defaultdict(int),
            'subjective_factors': defaultdict(int)
        }
        
        for result in results:
            for factor in result['objective_factors']:
                summary['objective_factors'][factor['category']] += 1
            for factor in result['subjective_factors']:
                summary['subjective_factors'][factor['category']] += 1
        
        return summary

    def save_results(self, results: Dict[str, Any], output_path: str):
        """Save analysis results to a JSON file."""
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)

    def close(self):
        """Close database connection if open."""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")

def main():
    # MIMIC database configuration
    db_config = {
        'dbname': 'mimic',
        'user': 'your_username',
        'password': 'your_password',
        'host': 'localhost',
        'port': '5432'
    }
    
    analyzer = MIMICTherapyNotesAnalyzer(db_config)
    
    try:
        # Process notes from MIMIC database
        results = analyzer.process_notes_from_mimic(batch_size=1000)
        
        # Save results with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f'mimic_therapy_analysis_results_{timestamp}.json'
        analyzer.save_results(results, output_path)
        
        # Print summary
        print("\nAnalysis Summary:")
        print(f"Total notes analyzed: {results['total_notes']}")
        print(f"Co-treatment mentions: {results['co_treatment_mentions']} ({results['co_treatment_percentage']:.1f}%)")
        
        print("\nObjective Factors:")
        for factor, count in results['objective_factors'].items():
            print(f"{factor}: {count}")
        
        print("\nSubjective Factors:")
        for factor, count in results['subjective_factors'].items():
            print(f"{factor}: {count}")
            
    finally:
        analyzer.close()

if __name__ == "__main__":
    main() 