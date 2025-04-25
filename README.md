# MIMIC Therapy Notes Analyzer

This tool analyzes therapy notes from the MIMIC (Medical Information Mart for Intensive Care) database to identify factors contributing to PT/OT/SLP co-treatment needs.

## Features

- Analyzes MIMIC-III and MIMIC-IV clinical notes
- Identifies both objective and subjective factors in therapy notes
- Extracts context around identified factors
- Quantifies frequency of co-treatment mentions
- Provides detailed analysis of contributing factors
- Saves results in JSON format
- Batch processing for large datasets

## Code Components

### 1. Core Classes

#### `CoTreatmentFactor` Dataclass
```python
@dataclass
class CoTreatmentFactor:
    category: str          # Main category of the factor
    subcategory: str       # Specific subcategory
    description: str       # Detailed description
    frequency: int = 0     # How often this factor appears
    confidence_score: float = 0.0  # Confidence in the identification
```
This class represents a single factor that might contribute to co-treatment decisions.

#### `MIMICTherapyNotesAnalyzer` Class
The main class that handles the analysis of therapy notes from the MIMIC database.

### 2. Pattern Matching

#### Objective Variables
```python
objective_patterns = {
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
```
Patterns for identifying objective clinical factors in the notes.

#### Subjective Variables
```python
subjective_patterns = {
    'scheduling': r'(scheduling|coordinate|waiting|time constraint|appointment)',
    'complexity': r'(complex|multi-system|multiple deficits|significant|challenging)',
    'expertise': r'(expertise|experience|skill|knowledge|proficiency)',
    'co_treatment': r'(co-treatment|joint session|combined|collaborative|team approach)',
    # MIMIC-specific patterns
    'mimic_careunit': r'(careunit|unit_type|location)',
    'mimic_service': r'(service|department|specialty)'
}
```
Patterns for identifying subjective factors and contextual information.

### 3. Database Integration

#### Connection Management
```python
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
```
Handles connection to the MIMIC PostgreSQL database.

#### Note Processing
```python
def process_notes_from_mimic(self, batch_size: int = 1000):
    """Process notes from MIMIC database in batches."""
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
```
Retrieves and processes notes from the MIMIC database in batches.

### 4. Analysis Methods

#### Note Processing
```python
def process_note(self, note_text: str) -> Dict[str, Any]:
    """Process a single therapy note and extract relevant factors."""
    findings = {
        'objective_factors': [],
        'subjective_factors': [],
        'co_treatment_mentioned': False
    }
```
Analyzes individual notes to identify factors and their context.

#### Context Extraction
```python
def _get_context(self, text: str, start: int, end: int, window: int = 100) -> str:
    """Extract context around a match."""
    start = max(0, start - window)
    end = min(len(text), end + window)
    return text[start:end]
```
Extracts surrounding text for identified factors.

#### Results Summarization
```python
def _summarize_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize the analysis results."""
    summary = {
        'total_notes': self.total_notes,
        'co_treatment_mentions': self.co_treatment_mentions,
        'co_treatment_percentage': (self.co_treatment_mentions / self.total_notes * 100) if self.total_notes > 0 else 0,
        'objective_factors': defaultdict(int),
        'subjective_factors': defaultdict(int)
    }
```
Combines and summarizes results from multiple notes.

## Installation

1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Configure database connection:
   ```python
   db_config = {
       'dbname': 'mimic',
       'user': 'your_username',
       'password': 'your_password',
       'host': 'localhost',
       'port': '5432'
   }
   ```

2. Run the analyzer:
   ```python
   from therapy_notes_analyzer import MIMICTherapyNotesAnalyzer
   
   analyzer = MIMICTherapyNotesAnalyzer(db_config)
   try:
       results = analyzer.process_notes_from_mimic(batch_size=1000)
       analyzer.save_results(results, 'output.json')
   finally:
       analyzer.close()
   ```

## Output Format

The analyzer produces a JSON file with the following structure:
```json
{
  "total_notes": <number>,
  "co_treatment_mentions": <number>,
  "co_treatment_percentage": <percentage>,
  "objective_factors": {
    "vitals": <count>,
    "diagnosis": <count>,
    "mimic_diagnosis": <count>,
    ...
  },
  "subjective_factors": {
    "scheduling": <count>,
    "complexity": <count>,
    "mimic_careunit": <count>,
    ...
  }
}
```

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is licensed under the MIT License - see the LICENSE file for details. 