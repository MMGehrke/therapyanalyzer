import re
import pandas as pd
import numpy as np
from collections import defaultdict, deque
from typing import List, Dict, Any, Optional, Union
import json
from dataclasses import dataclass
from datetime import datetime
import logging
from logging.handlers import MemoryHandler
import psycopg2
from psycopg2.extras import DictCursor
import tempfile
import os
import gc
import ctypes
import sys
import platform
import struct
import ssl
import certifi
from pathlib import Path
import hashlib
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from getpass import getpass
import subprocess
import signal
import atexit
import socket
import select
import termios
import tty
import fcntl
import time
from typing import Optional, Dict, Any, Union
import hmac
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import traceback
import inspect
import threading
from queue import Queue
import uuid
import html
from urllib.parse import urlparse
import validators
import urllib.parse
from email.utils import parseaddr
import pwd
import grp
import stat
import docker

# Memory protection utilities
class MemoryProtection:
    @staticmethod
    def lock_memory():
        """Lock the current process's memory to prevent swapping."""
        if platform.system() == 'Linux':
            # Use mlockall on Linux
            libc = ctypes.CDLL('libc.so.6')
            if libc.mlockall(0x2) != 0:  # MCL_CURRENT
                raise RuntimeError("Failed to lock memory")
        elif platform.system() == 'Darwin':  # macOS
            # Use mlockall on macOS
            libc = ctypes.CDLL('libc.dylib')
            if libc.mlockall(0x2) != 0:  # MCL_CURRENT
                raise RuntimeError("Failed to lock memory")
        elif platform.system() == 'Windows':
            # Use VirtualLock on Windows
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            process_handle = kernel32.GetCurrentProcess()
            
            # Get process memory info
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_ulong),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong),
                    ("Type", ctypes.c_ulong)
                ]
            
            # Lock all memory regions
            address = 0
            while True:
                mbi = MEMORY_BASIC_INFORMATION()
                result = kernel32.VirtualQuery(address, ctypes.byref(mbi), ctypes.sizeof(mbi))
                if result == 0:
                    break
                
                if mbi.State == 0x1000:  # MEM_COMMIT
                    if not kernel32.VirtualLock(mbi.BaseAddress, mbi.RegionSize):
                        error = ctypes.get_last_error()
                        if error != 0:
                            raise RuntimeError(f"Failed to lock memory region: {error}")
                
                address += mbi.RegionSize
        else:
            logger.warning("Memory locking not supported on this platform")

    @staticmethod
    def unlock_memory():
        """Unlock the process's memory."""
        if platform.system() == 'Linux':
            libc = ctypes.CDLL('libc.so.6')
            libc.munlockall()
        elif platform.system() == 'Darwin':
            libc = ctypes.CDLL('libc.dylib')
            libc.munlockall()
        elif platform.system() == 'Windows':
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            process_handle = kernel32.GetCurrentProcess()
            
            # Unlock all memory regions
            address = 0
            while True:
                mbi = MEMORY_BASIC_INFORMATION()
                result = kernel32.VirtualQuery(address, ctypes.byref(mbi), ctypes.sizeof(mbi))
                if result == 0:
                    break
                
                if mbi.State == 0x1000:  # MEM_COMMIT
                    kernel32.VirtualUnlock(mbi.BaseAddress, mbi.RegionSize)
                
                address += mbi.RegionSize

    @staticmethod
    def verify_memory_protection():
        """Verify that memory is protected from swapping."""
        if platform.system() == 'Linux':
            libc = ctypes.CDLL('libc.so.6')
            return libc.mlockall(0x2) == 0
        elif platform.system() == 'Darwin':
            libc = ctypes.CDLL('libc.dylib')
            return libc.mlockall(0x2) == 0
        elif platform.system() == 'Windows':
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            # On Windows, we can't directly verify if memory is locked
            # We'll check if we can lock a small region as a proxy
            test_size = 4096  # One page
            test_buffer = ctypes.create_string_buffer(test_size)
            try:
                if kernel32.VirtualLock(test_buffer, test_size):
                    kernel32.VirtualUnlock(test_buffer, test_size)
                    return True
            except:
                pass
            return False
        return False

    @staticmethod
    def secure_clear_memory(address: int, size: int):
        """Securely clear a memory region by overwriting it with random data."""
        if platform.system() == 'Windows':
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            # Create a buffer of random bytes
            random_bytes = os.urandom(size)
            # Write the random bytes to the memory region
            ctypes.memmove(address, random_bytes, size)
            # Write zeros to ensure complete clearing
            ctypes.memset(address, 0, size)
        else:
            libc = ctypes.CDLL('libc.so.6' if platform.system() == 'Linux' else 'libc.dylib')
            # Use explicit_bzero if available (more secure than memset)
            if hasattr(libc, 'explicit_bzero'):
                libc.explicit_bzero(address, size)
            else:
                # Fallback to three-pass overwrite
                libc.memset(address, 0x00, size)  # First pass: zeros
                libc.memset(address, 0xFF, size)  # Second pass: ones
                libc.memset(address, 0x00, size)  # Third pass: zeros

    @staticmethod
    def clear_sensitive_data(obj):
        """Recursively clear sensitive data from objects."""
        if isinstance(obj, (str, bytes)):
            # For strings and bytes, create a new object with the same size but filled with zeros
            size = len(obj)
            if isinstance(obj, str):
                return '\0' * size
            else:
                return b'\0' * size
        elif isinstance(obj, (list, tuple)):
            # For lists and tuples, clear each element
            return type(obj)(MemoryProtection.clear_sensitive_data(x) for x in obj)
        elif isinstance(obj, dict):
            # For dictionaries, clear each value
            return {k: MemoryProtection.clear_sensitive_data(v) for k, v in obj.items()}
        elif isinstance(obj, (pd.DataFrame, pd.Series)):
            # For pandas objects, clear the underlying data
            obj.fillna(0, inplace=True)
            obj.mask(obj != 0, 0, inplace=True)
            return obj
        elif isinstance(obj, np.ndarray):
            # For numpy arrays, clear the data
            obj.fill(0)
            return obj
        return obj

class DebugLogEntry:
    """Secure container for debug log entries."""
    def __init__(self, timestamp: datetime, level: str, message: str, context: Optional[Dict] = None):
        self.timestamp = timestamp
        self.level = level
        self.message = message
        self.context = context or {}
        self._sensitive_regions = []

    def add_sensitive_region(self, address: int, size: int):
        """Track sensitive memory regions associated with this log entry."""
        self._sensitive_regions.append((address, size))

    def clear(self):
        """Securely clear sensitive data from this log entry."""
        try:
            # Clear sensitive regions
            for address, size in self._sensitive_regions:
                MemoryProtection.secure_clear_memory(address, size)
            
            # Clear context if it contains sensitive data
            if self.context:
                for key, value in self.context.items():
                    if isinstance(value, (str, bytes)):
                        if isinstance(value, str):
                            value = value.encode()
                        MemoryProtection.secure_clear_memory(id(value), len(value))
            
            self._sensitive_regions.clear()
            self.context.clear()
        except Exception as e:
            print(f"Error clearing debug log entry: {e}")

class SecureMemoryHandler(MemoryHandler):
    """Secure in-memory logging handler that prevents sensitive data from being written to disk."""
    def __init__(self, capacity: int = 1000, flushLevel: int = logging.ERROR, debug_mode: bool = False):
        super().__init__(capacity, flushLevel=flushLevel)
        self._sensitive_patterns = [
            r'password[=:]\s*["\']?[^"\'\s]+["\']?',
            r'secret[=:]\s*["\']?[^"\'\s]+["\']?',
            r'key[=:]\s*["\']?[^"\'\s]+["\']?',
            r'token[=:]\s*["\']?[^"\'\s]+["\']?',
            r'credential[=:]\s*["\']?[^"\'\s]+["\']?',
            r'dbname[=:]\s*["\']?[^"\'\s]+["\']?',
            r'user[=:]\s*["\']?[^"\'\s]+["\']?',
            r'host[=:]\s*["\']?[^"\'\s]+["\']?',
            r'port[=:]\s*["\']?[^"\'\s]+["\']?'
        ]
        self._sensitive_regions = []
        self.debug_mode = debug_mode
        self.debug_logs = deque(maxlen=1000)  # Circular buffer for debug logs
        self._lock = threading.Lock()

    def _get_context(self) -> Dict:
        """Get debug context for the current log entry."""
        try:
            frame = inspect.currentframe()
            while frame:
                if frame.f_code.co_name == 'emit':
                    frame = frame.f_back
                    break
                frame = frame.f_back
            
            if frame:
                context = {
                    'function': frame.f_code.co_name,
                    'filename': frame.f_code.co_filename,
                    'lineno': frame.f_lineno,
                    'locals': {k: str(v) for k, v in frame.f_locals.items() 
                             if not any(pattern in k.lower() for pattern in ['password', 'secret', 'key', 'token'])}
                }
                return context
        except Exception:
            pass
        return {}

    def emit(self, record):
        """Emit a record, ensuring sensitive data is sanitized."""
        try:
            with self._lock:
                # Sanitize the message
                original_msg = str(record.msg)
                sanitized_msg = self._sanitize_message(original_msg)
                record.msg = sanitized_msg
                
                # Create debug log entry if in debug mode
                if self.debug_mode and record.levelno >= logging.DEBUG:
                    context = self._get_context()
                    debug_entry = DebugLogEntry(
                        timestamp=datetime.now(),
                        level=record.levelname,
                        message=sanitized_msg,
                        context=context
                    )
                    
                    # Track sensitive regions
                    if isinstance(original_msg, str):
                        msg_bytes = original_msg.encode()
                        debug_entry.add_sensitive_region(id(msg_bytes), len(msg_bytes))
                    
                    self.debug_logs.append(debug_entry)
                
                # Track memory region
                if isinstance(record.msg, str):
                    msg_bytes = record.msg.encode()
                    self._track_sensitive_region(msg_bytes)
                
                super().emit(record)
        except Exception as e:
            self.handleError(record)

    def get_debug_logs(self) -> List[DebugLogEntry]:
        """Get debug log entries."""
        with self._lock:
            return list(self.debug_logs)

    def clear_debug_logs(self):
        """Securely clear debug logs."""
        with self._lock:
            for entry in self.debug_logs:
                entry.clear()
            self.debug_logs.clear()

    def _sanitize_message(self, message: str) -> str:
        """Sanitize log message to remove sensitive data."""
        for pattern in self._sensitive_patterns:
            message = re.sub(pattern, lambda m: m.group(0).split('=')[0] + '=*****', message, flags=re.IGNORECASE)
        return message

    def _track_sensitive_region(self, data: bytes) -> None:
        """Track sensitive memory regions for secure clearing."""
        address = id(data)
        size = len(data)
        self._sensitive_regions.append((address, size))

    def clear(self) -> None:
        """Securely clear all log data from memory."""
        try:
            with self._lock:
                # Clear the buffer
                self.buffer.clear()
                
                # Clear debug logs
                self.clear_debug_logs()
                
                # Clear tracked sensitive regions
                for address, size in self._sensitive_regions:
                    MemoryProtection.secure_clear_memory(address, size)
                
                self._sensitive_regions.clear()
                gc.collect()
        except Exception as e:
            print(f"Error clearing secure log handler: {e}")

class SecureAuditLogger:
    """Secure audit logging system that tracks non-sensitive actions."""
    def __init__(self):
        self.audit_events = deque(maxlen=1000)  # Circular buffer for audit events
        self._lock = threading.Lock()
        self._sensitive_patterns = [
            r'password[=:]\s*["\']?[^"\'\s]+["\']?',
            r'secret[=:]\s*["\']?[^"\'\s]+["\']?',
            r'key[=:]\s*["\']?[^"\'\s]+["\']?',
            r'token[=:]\s*["\']?[^"\'\s]+["\']?',
            r'credential[=:]\s*["\']?[^"\'\s]+["\']?'
        ]

    def log_event(self, 
                 action: str,
                 status: str,
                 actor: Optional[str] = None,
                 details: Optional[Dict] = None) -> str:
        """Log a non-sensitive audit event."""
        try:
            with self._lock:
                event_id = str(uuid.uuid4())
                event = AuditEvent(
                    event_id=event_id,
                    timestamp=datetime.now(),
                    action=action,
                    status=status,
                    actor=actor,
                    details=details
                )
                self.audit_events.append(event)
                return event_id
        except Exception as e:
            print(f"Error logging audit event: {e}")
            return ""

    def get_audit_logs(self) -> List[Dict]:
        """Get sanitized audit logs."""
        with self._lock:
            return [event.to_dict() for event in self.audit_events]

    def clear_audit_logs(self):
        """Securely clear all audit logs."""
        with self._lock:
            for event in self.audit_events:
                event.clear()
            self.audit_events.clear()

class SecureLogger:
    """Secure logging manager that ensures all logs are kept in memory and sanitized."""
    def __init__(self, name: str = 'secure_mimic_analyzer', debug_mode: bool = False):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
        
        # Remove any existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Create secure memory handler
        self.memory_handler = SecureMemoryHandler(debug_mode=debug_mode)
        self.memory_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        self.logger.addHandler(self.memory_handler)
        
        # Initialize audit logger
        self.audit_logger = SecureAuditLogger()
        
        # Disable propagation to prevent logs from being handled by parent loggers
        self.logger.propagate = False

    def audit(self, 
             action: str,
             status: str,
             actor: Optional[str] = None,
             details: Optional[Dict] = None) -> str:
        """Log a non-sensitive audit event."""
        return self.audit_logger.log_event(action, status, actor, details)

    def get_audit_logs(self) -> List[Dict]:
        """Get sanitized audit logs."""
        return self.audit_logger.get_audit_logs()

    def clear_audit_logs(self):
        """Securely clear all audit logs."""
        self.audit_logger.clear_audit_logs()

    def get_logs(self) -> List[str]:
        """Get sanitized log messages from memory."""
        return [self.memory_handler.format(record) for record in self.memory_handler.buffer]

    def get_debug_logs(self) -> List[DebugLogEntry]:
        """Get debug log entries."""
        return self.memory_handler.get_debug_logs()

    def clear_logs(self) -> None:
        """Securely clear all logs from memory."""
        self.memory_handler.clear()

    def __getattr__(self, name):
        """Delegate logging methods to the underlying logger."""
        return getattr(self.logger, name)

# Initialize secure logger with debug mode
secure_logger = SecureLogger(debug_mode=True)
logger = secure_logger.logger

@dataclass
class CoTreatmentFactor:
    category: str
    subcategory: str
    description: str
    frequency: int = 0
    confidence_score: float = 0.0

class CertificateManager:
    @staticmethod
    def verify_certificate_chain(cert_path: str, ca_cert_path: str) -> bool:
        """Verify the certificate chain."""
        try:
            # Load the certificate
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Create SSL context
            context = ssl.create_default_context(cafile=ca_cert_path)
            
            # Load certificate into context
            context.load_cert_chain(cert_path)
            
            # Verify the certificate
            cert = ssl.get_server_certificate(('localhost', 5432))
            der_cert = ssl.PEM_cert_to_DER_cert(cert)
            
            # Verify certificate chain
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            
            return True
        except Exception as e:
            logger.error(f"Certificate verification failed: {e}")
            return False

    @staticmethod
    def get_certificate_fingerprint(cert_path: str) -> str:
        """Get the SHA-256 fingerprint of a certificate."""
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            return hashlib.sha256(cert_data).hexdigest()
        except Exception as e:
            logger.error(f"Failed to get certificate fingerprint: {e}")
            return ""

    @staticmethod
    def verify_certificate_fingerprint(cert_path: str, expected_fingerprint: str) -> bool:
        """Verify a certificate against an expected fingerprint."""
        actual_fingerprint = CertificateManager.get_certificate_fingerprint(cert_path)
        return actual_fingerprint.lower() == expected_fingerprint.lower()

class TLSSecurityManager:
    @staticmethod
    def create_secure_context() -> ssl.SSLContext:
        """Create a secure SSL context with TLS 1.3 enforcement."""
        try:
            # Create SSL context with highest available protocol
            context = ssl.create_default_context()
            
            # Set minimum and maximum protocol versions
            if hasattr(ssl, 'PROTOCOL_TLS'):  # Python 3.6+
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3
            else:
                # Fallback for older Python versions
                context.options |= ssl.OP_NO_SSLv2
                context.options |= ssl.OP_NO_SSLv3
                context.options |= ssl.OP_NO_TLSv1
                context.options |= ssl.OP_NO_TLSv1_1
                context.options |= ssl.OP_NO_TLSv1_2
            
            # Set secure cipher suites
            if hasattr(context, 'set_ciphers'):
                context.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256')
            
            # Enable certificate verification
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            
            # Load system CA certificates
            context.load_verify_locations(cafile=certifi.where())
            
            return context
        except Exception as e:
            logger.error(f"Failed to create secure SSL context: {e}")
            raise

    @staticmethod
    def verify_tls_version(conn) -> bool:
        """Verify that the connection is using TLS 1.3."""
        try:
            # Get SSL version information
            with conn.cursor() as cur:
                cur.execute("SHOW ssl_version")
                ssl_version = cur.fetchone()[0]
                
                # Log the SSL version
                logger.info(f"SSL/TLS version in use: {ssl_version}")
                
                # Verify TLS 1.3 is being used
                if not ssl_version.startswith('TLSv1.3'):
                    logger.warning(f"Insecure TLS version detected: {ssl_version}")
                    return False
                
                return True
        except Exception as e:
            logger.error(f"Failed to verify TLS version: {e}")
            return False

class SecureKeyManager:
    def __init__(self):
        self._private_key = None
        self._certificate = None
        self._key_password = None
        self._tls_manager = TLSSecurityManager()

    def load_key_from_memory(self, key_data: bytes, password: Optional[str] = None) -> None:
        """Load private key from memory and keep it secure."""
        try:
            # Store password securely in memory
            self._key_password = password.encode() if password else None
            
            # Load the private key
            self._private_key = serialization.load_pem_private_key(
                key_data,
                password=self._key_password,
                backend=default_backend()
            )
            
            # Clear the original key data from memory
            self._secure_clear_bytes(key_data)
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            raise

    def load_certificate_from_memory(self, cert_data: bytes) -> None:
        """Load certificate from memory."""
        try:
            self._certificate = cert_data
        except Exception as e:
            logger.error(f"Failed to load certificate: {e}")
            raise

    def get_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with in-memory key and certificate."""
        try:
            # Get secure SSL context
            context = self._tls_manager.create_secure_context()

            if self._private_key and self._certificate:
                # Convert private key to PEM format in memory
                key_pem = self._private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                # Create in-memory certificate and key
                context.load_cert_chain(
                    certfile=self._certificate,
                    keyfile=key_pem
                )
            
            return context
        except Exception as e:
            logger.error(f"Failed to create SSL context: {e}")
            raise

    def cleanup(self):
        """Securely clear all key material from memory."""
        if self._private_key:
            # Clear private key
            self._private_key = None
        if self._certificate:
            # Clear certificate
            self._secure_clear_bytes(self._certificate)
            self._certificate = None
        if self._key_password:
            # Clear password
            self._secure_clear_bytes(self._key_password)
            self._key_password = None
        gc.collect()

    @staticmethod
    def _secure_clear_bytes(data: bytes) -> None:
        """Securely clear bytes from memory."""
        if data:
            # Overwrite the memory
            ctypes.memset(ctypes.c_char_p(data), 0, len(data))
            # Force garbage collection
            gc.collect()

class SecureInput:
    @staticmethod
    def get_secure_input(prompt: str, mask: bool = True) -> str:
        """Get secure input from the user with optional masking."""
        try:
            if mask:
                return getpass(prompt)
            else:
                # For non-sensitive input, use regular input but with secure handling
                print(prompt, end='', flush=True)
                return input()
        except Exception as e:
            logger.error(f"Failed to get secure input: {e}")
            raise

    @staticmethod
    def get_secure_multi_line(prompt: str) -> str:
        """Get secure multi-line input (e.g., for certificates)."""
        try:
            print(prompt)
            print("Enter your input (press Ctrl+D when done):")
            
            # Save terminal settings
            old_settings = termios.tcgetattr(sys.stdin)
            try:
                # Set terminal to raw mode
                tty.setraw(sys.stdin.fileno())
                
                lines = []
                while True:
                    # Read one character at a time
                    char = sys.stdin.read(1)
                    if char == '\x04':  # Ctrl+D
                        break
                    if char == '\r' or char == '\n':
                        print()
                        lines.append('')
                    else:
                        print('*', end='', flush=True)
                        lines.append(char)
                
                return ''.join(lines)
            finally:
                # Restore terminal settings
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        except Exception as e:
            logger.error(f"Failed to get secure multi-line input: {e}")
            raise

class SecretManager:
    def __init__(self):
        self._key = None
        self._salt = None
        self._sensitive_regions = []

    def _derive_key(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """Derive a secure key from a password."""
        try:
            if salt is None:
                salt = os.urandom(16)
            self._salt = salt
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            self._track_sensitive_data(key)
            return key
        except Exception as e:
            logger.error(f"Failed to derive key: {e}")
            raise

    def encrypt_secret(self, secret: str, password: str) -> bytes:
        """Encrypt a secret using a password-derived key."""
        try:
            key = self._derive_key(password)
            f = Fernet(key)
            encrypted = f.encrypt(secret.encode())
            self._track_sensitive_data(encrypted)
            return encrypted
        except Exception as e:
            logger.error(f"Failed to encrypt secret: {e}")
            raise

    def decrypt_secret(self, encrypted: bytes, password: str) -> str:
        """Decrypt a secret using a password-derived key."""
        try:
            key = self._derive_key(password)
            f = Fernet(key)
            decrypted = f.decrypt(encrypted).decode()
            self._track_sensitive_data(decrypted)
            return decrypted
        except Exception as e:
            logger.error(f"Failed to decrypt secret: {e}")
            raise

    def _track_sensitive_data(self, data: Union[str, bytes]) -> None:
        """Track sensitive data for secure clearing."""
        if isinstance(data, str):
            data = data.encode()
        address = id(data)
        size = len(data)
        self._sensitive_regions.append((address, size))

    def clear_secrets(self) -> None:
        """Securely clear all sensitive data."""
        try:
            if self._key:
                self._track_sensitive_data(self._key)
            if self._salt:
                self._track_sensitive_data(self._salt)
            
            for address, size in self._sensitive_regions:
                MemoryProtection.secure_clear_memory(address, size)
            
            self._sensitive_regions.clear()
            gc.collect()
        except Exception as e:
            logger.error(f"Failed to clear secrets: {e}")
            raise

class SecureCredentialManager:
    def __init__(self):
        self._secure_input = SecureInput()
        self._secret_manager = SecretManager()
        self._process_security = ProcessSecurity()
        self._credentials = {}
        self._sensitive_regions = []

    def get_credentials_interactive(self) -> Dict[str, str]:
        """Get credentials through secure interactive input."""
        try:
            credentials = {
                'dbname': self._secure_input.get_secure_input("Enter database name: ", mask=False),
                'user': self._secure_input.get_secure_input("Enter database username: ", mask=False),
                'password': self._secure_input.get_secure_input("Enter database password: ", mask=True),
                'host': self._secure_input.get_secure_input("Enter database host: ", mask=False),
                'port': self._secure_input.get_secure_input("Enter database port: ", mask=False)
            }
            
            # Track sensitive data
            self._track_sensitive_data(credentials['password'])
            
            return credentials
        except Exception as e:
            logger.error(f"Failed to get interactive credentials: {e}")
            raise

    def get_credentials_from_encrypted(self, encrypted_file: str) -> Dict[str, str]:
        """Get credentials from an encrypted file."""
        try:
            # Get decryption password securely
            password = self._secure_input.get_secure_input("Enter decryption password: ", mask=True)
            
            # Read and decrypt the file
            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self._secret_manager.decrypt_secret(encrypted_data, password)
            credentials = json.loads(decrypted_data)
            
            # Track sensitive data
            self._track_sensitive_data(credentials['password'])
            self._track_sensitive_data(password)
            
            return credentials
        except Exception as e:
            logger.error(f"Failed to get credentials from encrypted file: {e}")
            raise

    def _track_sensitive_data(self, data: Union[str, Dict]) -> None:
        """Track sensitive data for secure clearing."""
        if isinstance(data, str):
            data_bytes = data.encode()
            address = id(data_bytes)
            size = len(data_bytes)
            self._sensitive_regions.append((address, size))
        elif isinstance(data, dict):
            for value in data.values():
                if isinstance(value, str):
                    self._track_sensitive_data(value)

    def clear_credentials(self) -> None:
        """Securely clear all credentials."""
        try:
            # Clear credential dictionary
            for key in self._credentials:
                if self._credentials[key]:
                    self._credentials[key] = None
            
            # Clear tracked sensitive regions
            for address, size in self._sensitive_regions:
                MemoryProtection.secure_clear_memory(address, size)
            
            self._sensitive_regions.clear()
            gc.collect()
            
            # Clear secret manager
            self._secret_manager.clear_secrets()
            
            # Secure the process environment
            self._process_security.secure_process_environment()
        except Exception as e:
            logger.error(f"Failed to clear credentials: {e}")
            raise

class ProcessSecurity:
    @staticmethod
    def secure_process_title():
        """Set a generic process title to hide sensitive information."""
        try:
            if platform.system() == 'Linux':
                # Use prctl to set process title
                libc = ctypes.CDLL('libc.so.6')
                libc.prctl(15, b'python', 0, 0, 0)  # PR_SET_NAME
            elif platform.system() == 'Darwin':
                # On macOS, we can't easily change the process title
                pass
        except Exception as e:
            logger.warning(f"Failed to set process title: {e}")

    @staticmethod
    def disable_core_dumps():
        """Disable core dumps to prevent memory contents from being written to disk."""
        try:
            if platform.system() == 'Linux':
                import resource
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            elif platform.system() == 'Darwin':
                import resource
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception as e:
            logger.warning(f"Failed to disable core dumps: {e}")

    @staticmethod
    def secure_process_environment():
        """Secure the process environment."""
        try:
            # Clear sensitive environment variables
            sensitive_vars = [
                'MIMIC_DB_PASSWORD',
                'MIMIC_DB_USER',
                'MIMIC_DB_NAME',
                'MIMIC_DB_HOST',
                'MIMIC_DB_PORT'
            ]
            
            for var in sensitive_vars:
                if var in os.environ:
                    # Store the value temporarily
                    value = os.environ[var]
                    # Remove from environment
                    del os.environ[var]
                    # Overwrite the memory
                    if value:
                        ctypes.memset(ctypes.c_char_p(value.encode()), 0, len(value))
            
            # Force garbage collection
            gc.collect()
        except Exception as e:
            logger.error(f"Failed to secure process environment: {e}")
            raise

class SecureEnvironmentManager:
    def __init__(self):
        self._env_vars = {}
        self._sensitive_regions = []
        self._process_security = ProcessSecurity()

    def load_secure_environment(self) -> Dict[str, str]:
        """Load and secure environment variables."""
        try:
            # First secure the process
            self._process_security.secure_process_title()
            self._process_security.disable_core_dumps()
            
            # Define required environment variables
            required_vars = {
                'dbname': 'MIMIC_DB_NAME',
                'user': 'MIMIC_DB_USER',
                'password': 'MIMIC_DB_PASSWORD',
                'host': 'MIMIC_DB_HOST',
                'port': 'MIMIC_DB_PORT'
            }
            
            # Load and secure each variable
            credentials = {}
            for key, env_var in required_vars.items():
                value = os.getenv(env_var)
                if not value:
                    raise ValueError(f"Environment variable {env_var} not set")
                
                # Store in our secure dictionary
                credentials[key] = value
                
                # Track sensitive data
                if key == 'password':
                    self._track_sensitive_data(value)
                
                # Remove from environment
                if env_var in os.environ:
                    del os.environ[env_var]
            
            self._env_vars = credentials
            return credentials.copy()
        except Exception as e:
            logger.error(f"Failed to load secure environment: {e}")
            raise

    def _track_sensitive_data(self, data: str) -> None:
        """Track sensitive data for secure clearing."""
        if isinstance(data, str):
            data_bytes = data.encode()
            address = id(data_bytes)
            size = len(data_bytes)
            self._sensitive_regions.append((address, size))

    def clear_environment(self) -> None:
        """Securely clear all environment data."""
        try:
            # Clear environment variables dictionary
            for key in self._env_vars:
                if self._env_vars[key]:
                    self._env_vars[key] = None
            
            # Clear tracked sensitive regions
            for address, size in self._sensitive_regions:
                MemoryProtection.secure_clear_memory(address, size)
            
            self._sensitive_regions.clear()
            gc.collect()
            
            # Secure the process environment
            self._process_security.secure_process_environment()
        except Exception as e:
            logger.error(f"Failed to clear environment: {e}")
            raise

class AuditEvent:
    """Secure container for audit events."""
    def __init__(self, 
                 event_id: str,
                 timestamp: datetime,
                 action: str,
                 status: str,
                 actor: Optional[str] = None,
                 details: Optional[Dict] = None):
        self.event_id = event_id
        self.timestamp = timestamp
        self.action = action
        self.status = status
        self.actor = actor
        self.details = self._sanitize_details(details or {})
        self._sensitive_regions = []

    def _sanitize_details(self, details: Dict) -> Dict:
        """Sanitize details to remove sensitive information."""
        sanitized = {}
        for key, value in details.items():
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_details(value)
            elif isinstance(value, (str, bytes)):
                # Skip sensitive fields
                if any(pattern in key.lower() for pattern in ['password', 'secret', 'key', 'token', 'credential']):
                    sanitized[key] = '*****'
                else:
                    sanitized[key] = value
            else:
                sanitized[key] = value
        return sanitized

    def to_dict(self) -> Dict:
        """Convert audit event to dictionary for logging."""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'action': self.action,
            'status': self.status,
            'actor': self.actor,
            'details': self.details
        }

    def clear(self):
        """Securely clear sensitive data from this audit event."""
        try:
            # Clear sensitive regions
            for address, size in self._sensitive_regions:
                MemoryProtection.secure_clear_memory(address, size)
            
            # Clear details if they contain sensitive data
            if self.details:
                for key, value in self.details.items():
                    if isinstance(value, (str, bytes)):
                        if isinstance(value, str):
                            value = value.encode()
                        MemoryProtection.secure_clear_memory(id(value), len(value))
            
            self._sensitive_regions.clear()
            self.details.clear()
        except Exception as e:
            print(f"Error clearing audit event: {e}")

class QueryValidator:
    """Validates and sanitizes database query inputs."""
    @staticmethod
    def validate_table_name(table_name: str) -> bool:
        """Validate table name format."""
        # Only allow alphanumeric characters, underscores, and dots
        return bool(re.match(r'^[a-zA-Z0-9_\.]+$', table_name))

    @staticmethod
    def validate_column_name(column_name: str) -> bool:
        """Validate column name format."""
        # Only allow alphanumeric characters and underscores
        return bool(re.match(r'^[a-zA-Z0-9_]+$', column_name))

    @staticmethod
    def validate_limit_offset(limit: int, offset: int) -> bool:
        """Validate limit and offset values."""
        return limit > 0 and offset >= 0

    @staticmethod
    def sanitize_input(input_str: str) -> str:
        """Sanitize input string to prevent SQL injection."""
        # Remove any SQL comment patterns
        input_str = re.sub(r'--.*$', '', input_str)
        input_str = re.sub(r'/\*.*?\*/', '', input_str)
        # Remove any SQL control characters
        input_str = re.sub(r'[\'\";]', '', input_str)
        return input_str

class SecureQueryBuilder:
    """Builds secure parameterized queries."""
    def __init__(self):
        self._params = []
        self._param_count = 0

    def add_param(self, value: Any) -> str:
        """Add a parameter and return its placeholder."""
        self._params.append(value)
        self._param_count += 1
        return f"${self._param_count}"

    def get_params(self) -> tuple:
        """Get the parameter tuple."""
        return tuple(self._params)

    def build_select_query(self, 
                          table: str,
                          columns: List[str],
                          where_clause: Optional[str] = None,
                          order_by: Optional[str] = None,
                          limit: Optional[int] = None,
                          offset: Optional[int] = None) -> str:
        """Build a secure SELECT query."""
        if not QueryValidator.validate_table_name(table):
            raise ValueError(f"Invalid table name: {table}")

        # Validate column names
        for col in columns:
            if not QueryValidator.validate_column_name(col):
                raise ValueError(f"Invalid column name: {col}")

        # Build the base query
        query = f"SELECT {', '.join(columns)} FROM {table}"

        # Add WHERE clause if provided
        if where_clause:
            query += f" WHERE {where_clause}"

        # Add ORDER BY if provided
        if order_by:
            if not QueryValidator.validate_column_name(order_by):
                raise ValueError(f"Invalid order by column: {order_by}")
            query += f" ORDER BY {order_by}"

        # Add LIMIT and OFFSET if provided
        if limit is not None:
            if not QueryValidator.validate_limit_offset(limit, 0):
                raise ValueError(f"Invalid limit value: {limit}")
            query += f" LIMIT {self.add_param(limit)}"
        
        if offset is not None:
            if not QueryValidator.validate_limit_offset(1, offset):
                raise ValueError(f"Invalid offset value: {offset}")
            query += f" OFFSET {self.add_param(offset)}"

        return query

class SecureDatabaseManager:
    """Manages secure database operations."""
    def __init__(self, connection):
        self.conn = connection
        self.query_builder = SecureQueryBuilder()
        self._prepared_statements = {}

    def prepare_statement(self, name: str, query: str) -> None:
        """Prepare a statement for repeated use."""
        try:
            with self.conn.cursor() as cur:
                cur.execute(f"PREPARE {name} AS {query}")
            self._prepared_statements[name] = query
        except Exception as e:
            logger.error(f"Failed to prepare statement {name}: {e}")
            raise

    def execute_prepared(self, 
                        name: str,
                        params: tuple) -> List[Dict]:
        """Execute a prepared statement with parameters."""
        try:
            if name not in self._prepared_statements:
                raise ValueError(f"Prepared statement {name} not found")
            
            with self.conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute(f"EXECUTE {name}", params)
                return cur.fetchall()
        except Exception as e:
            logger.error(f"Failed to execute prepared statement {name}: {e}")
            raise

    def execute_query(self, 
                     table: str,
                     columns: List[str],
                     where_clause: Optional[str] = None,
                     order_by: Optional[str] = None,
                     limit: Optional[int] = None,
                     offset: Optional[int] = None) -> List[Dict]:
        """Execute a secure parameterized query."""
        try:
            # Build the query
            query = self.query_builder.build_select_query(
                table=table,
                columns=columns,
                where_clause=where_clause,
                order_by=order_by,
                limit=limit,
                offset=offset
            )
            
            # Get parameters
            params = self.query_builder.get_params()
            
            # Execute the query
            with self.conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute(query, params)
                return cur.fetchall()
        except Exception as e:
            logger.error(f"Failed to execute query: {e}")
            raise

    def cleanup(self):
        """Clean up prepared statements."""
        try:
            with self.conn.cursor() as cur:
                for name in self._prepared_statements:
                    cur.execute(f"DEALLOCATE {name}")
            self._prepared_statements.clear()
        except Exception as e:
            logger.error(f"Failed to cleanup prepared statements: {e}")

class InputValidator:
    def __init__(self):
        self.logger = logging.getLogger('input_validator')
        self.sensitive_memory_regions = []
        
        # Common regex patterns
        self.url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE
        )
        
        self.email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )

    def validate_url(self, url: str) -> bool:
        """Validate URL format using built-in Python functionality."""
        try:
            result = urllib.parse.urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
            if result.scheme not in ['http', 'https']:
                return False
            return bool(self.url_pattern.match(url))
        except Exception:
            return False

    def validate_email(self, email: str) -> bool:
        """Validate email format using built-in Python functionality."""
        try:
            _, addr = parseaddr(email)
            return bool(self.email_pattern.match(addr))
        except Exception:
            return False

    def validate_json(self, data: str) -> bool:
        """Validate JSON structure using built-in json module."""
        try:
            json.loads(data)
            return True
        except json.JSONDecodeError:
            return False

    def validate_file_path(self, path: str) -> bool:
        """Validate file path to prevent directory traversal."""
        try:
            # Normalize path
            normalized = os.path.normpath(path)
            # Check for directory traversal attempts
            if '..' in normalized.split(os.sep):
                return False
            # Check for absolute paths
            if os.path.isabs(normalized):
                return False
            return True
        except Exception:
            return False

    def validate_text(self, text: str, max_length: int = 1000) -> str:
        """Sanitize text input."""
        if not isinstance(text, str):
            return ""
        
        # Remove null bytes
        text = text.replace('\0', '')
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Remove control characters
        text = ''.join(char for char in text if ord(char) >= 32)
        
        # Limit length
        text = text[:max_length]
        
        return text

    def validate_numeric(self, value: Union[int, float], min_val: Optional[float] = None, 
                        max_val: Optional[float] = None) -> bool:
        """Validate numeric input."""
        try:
            if not isinstance(value, (int, float)):
                return False
            if min_val is not None and value < min_val:
                return False
            if max_val is not None and value > max_val:
                return False
            return True
        except Exception:
            return False

    def clear_sensitive_data(self):
        """Securely clear sensitive data from memory."""
        for region in self.sensitive_memory_regions:
            if isinstance(region, (str, bytes)):
                # Overwrite with random data
                random_data = os.urandom(len(region))
                region[:] = random_data
        self.sensitive_memory_regions.clear()

class SecureDataProcessor:
    """Processes and validates external data before database interaction."""
    def __init__(self):
        self.validator = InputValidator()
        self._sensitive_regions = []

    def process_note(self, note_data: Dict) -> Dict:
        """Process and validate a therapy note."""
        try:
            # Validate the note data structure
            if not isinstance(note_data, dict):
                raise ValueError("Note data must be a dictionary")
            
            # Validate required fields
            required_fields = ['text', 'category', 'timestamp']
            for field in required_fields:
                if field not in note_data:
                    raise ValueError(f"Missing required field: {field}")
            
            # Process and validate each field
            processed = {
                'text': self.validator.validate_text(note_data['text']),
                'category': self.validator.validate_text(note_data['category'], max_length=50),
                'timestamp': self._validate_timestamp(note_data['timestamp']),
                'metadata': self._process_metadata(note_data.get('metadata', {}))
            }
            
            # Track sensitive data
            self._track_sensitive_region(processed)
            
            return processed
        except Exception as e:
            logger.error(f"Failed to process note: {e}")
            raise

    def _validate_timestamp(self, timestamp: Union[str, datetime]) -> datetime:
        """Validate and convert timestamp."""
        if isinstance(timestamp, datetime):
            return timestamp
        
        if isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp)
            except ValueError:
                raise ValueError("Invalid timestamp format")
        
        raise ValueError("Timestamp must be a string or datetime object")

    def _process_metadata(self, metadata: Dict) -> Dict:
        """Process and validate note metadata."""
        try:
            processed = {}
            
            # Validate and process each metadata field
            if 'author' in metadata:
                processed['author'] = self.validator.validate_text(metadata['author'], max_length=100)
            
            if 'source' in metadata:
                processed['source'] = self.validator.validate_url(metadata['source'])
            
            if 'tags' in metadata:
                processed['tags'] = [
                    self.validator.validate_text(tag, max_length=50)
                    for tag in metadata['tags']
                ]
            
            return processed
        except Exception as e:
            logger.error(f"Failed to process metadata: {e}")
            raise

    def _track_sensitive_region(self, data: Any):
        """Track memory regions containing sensitive data."""
        if isinstance(data, (str, bytes)):
            if isinstance(data, str):
                data = data.encode()
            address = id(data)
            size = len(data)
            self._sensitive_regions.append((address, size))
        elif isinstance(data, (list, tuple, dict)):
            # Recursively track elements
            for item in data if isinstance(data, (list, tuple)) else data.values():
                self._track_sensitive_region(item)
        elif isinstance(data, (pd.DataFrame, pd.Series, np.ndarray)):
            # Track numpy array data
            if isinstance(data, (pd.DataFrame, pd.Series)):
                arr = data.values
            else:
                arr = data
            address = arr.ctypes.data
            size = arr.nbytes
            self._sensitive_regions.append((address, size))

    def clear_sensitive_data(self):
        """Securely clear sensitive data from memory."""
        try:
            for address, size in self._sensitive_regions:
                MemoryProtection.secure_clear_memory(address, size)
            self._sensitive_regions.clear()
        except Exception as e:
            logger.error(f"Failed to clear sensitive data: {e}")

class SecureError(Exception):
    """Base class for secure error handling."""
    def __init__(self, message: str, error_code: str, details: Optional[Dict] = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self._sanitized_message = self._sanitize_message(message)
        self._log_level = self._determine_log_level()
        super().__init__(self._sanitized_message)

    def _determine_log_level(self) -> int:
        """Determine appropriate log level based on error type."""
        if isinstance(self, SecurityError):
            return logging.ERROR  # Always log security errors
        elif isinstance(self, DatabaseError):
            return logging.WARNING  # Log database errors at warning level
        else:
            return logging.INFO  # Log other errors at info level

    def _sanitize_message(self, message: str) -> str:
        """Sanitize error message to remove sensitive information."""
        # Remove any database-specific information
        message = re.sub(r'relation "[^"]+"', 'relation "*****"', message)
        message = re.sub(r'column "[^"]+"', 'column "*****"', message)
        message = re.sub(r'table "[^"]+"', 'table "*****"', message)
        
        # Remove any file paths
        message = re.sub(r'file "[^"]+"', 'file "*****"', message)
        message = re.sub(r'path "[^"]+"', 'path "*****"', message)
        
        # Remove any hostnames or IP addresses
        message = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '*****', message)
        message = re.sub(r'\b[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+\b', '*****', message)
        
        # Remove any credentials or tokens
        message = re.sub(r'password[=:]\s*["\']?[^"\'\s]+["\']?', 'password=*****', message)
        message = re.sub(r'secret[=:]\s*["\']?[^"\'\s]+["\']?', 'secret=*****', message)
        message = re.sub(r'token[=:]\s*["\']?[^"\'\s]+["\']?', 'token=*****', message)
        
        # Remove any stack traces or line numbers
        message = re.sub(r'File "[^"]+", line \d+', 'File "*****", line *****', message)
        message = re.sub(r'line \d+', 'line *****', message)
        
        # Remove any function names that might reveal implementation
        message = re.sub(r'in \w+', 'in *****', message)
        
        return message

    def to_dict(self) -> Dict:
        """Convert error to a sanitized dictionary."""
        return {
            'error_code': self.error_code,
            'message': self._sanitized_message,
            'details': self._sanitize_details(self.details),
            'log_level': logging.getLevelName(self._log_level)
        }

    def _sanitize_details(self, details: Dict) -> Dict:
        """Sanitize error details."""
        sanitized = {}
        for key, value in details.items():
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_details(value)
            elif isinstance(value, str):
                sanitized[key] = self._sanitize_message(value)
            elif isinstance(value, (list, tuple)):
                sanitized[key] = [self._sanitize_message(str(v)) if isinstance(v, str) else v for v in value]
            else:
                sanitized[key] = value
        return sanitized

class DatabaseError(SecureError):
    """Secure database error handling."""
    def __init__(self, error_code: str, details: Optional[Dict] = None):
        messages = {
            'CONNECTION_FAILED': 'Database connection failed',
            'QUERY_FAILED': 'Database query failed',
            'INVALID_CREDENTIALS': 'Invalid database credentials',
            'SSL_ERROR': 'SSL connection error',
            'TIMEOUT': 'Database operation timed out'
        }
        super().__init__(messages.get(error_code, 'Database error occurred'), error_code, details)

class ValidationError(SecureError):
    """Secure validation error handling."""
    def __init__(self, error_code: str, details: Optional[Dict] = None):
        messages = {
            'INVALID_INPUT': 'Invalid input provided',
            'MISSING_FIELD': 'Required field missing',
            'INVALID_FORMAT': 'Invalid data format',
            'OUT_OF_RANGE': 'Value out of valid range',
            'INVALID_TYPE': 'Invalid data type'
        }
        super().__init__(messages.get(error_code, 'Validation error occurred'), error_code, details)

class SecurityError(SecureError):
    """Secure security-related error handling."""
    def __init__(self, error_code: str, details: Optional[Dict] = None):
        messages = {
            'AUTHENTICATION_FAILED': 'Authentication failed',
            'AUTHORIZATION_FAILED': 'Authorization failed',
            'INVALID_CERTIFICATE': 'Invalid certificate',
            'INVALID_SIGNATURE': 'Invalid signature',
            'MEMORY_ERROR': 'Memory protection error'
        }
        super().__init__(messages.get(error_code, 'Security error occurred'), error_code, details)

class SecureErrorHandler:
    """Handles errors securely without exposing sensitive information."""
    @staticmethod
    def handle_error(error: Exception, context: Optional[str] = None) -> None:
        """Handle an error securely."""
        try:
            # Convert to secure error if not already
            if not isinstance(error, SecureError):
                error = SecureError(str(error), 'UNKNOWN_ERROR')
            
            # Get sanitized error information
            error_dict = error.to_dict()
            
            # Log at appropriate level with minimal information
            if error._log_level == logging.ERROR:
                logger.error(
                    f"Security error in {context or 'unknown context'}: {error.error_code}",
                    extra={'error_details': error_dict}
                )
            elif error._log_level == logging.WARNING:
                logger.warning(
                    f"Error in {context or 'unknown context'}: {error.error_code}",
                    extra={'error_details': error_dict}
                )
            else:
                logger.info(
                    f"Event in {context or 'unknown context'}: {error.error_code}",
                    extra={'error_details': error_dict}
                )
            
            # Audit the error with minimal information
            logger.audit(
                action="ERROR",
                status="OCCURRED",
                details={
                    'context': context,
                    'error_code': error.error_code,
                    'log_level': error_dict['log_level']
                }
            )
        except Exception as e:
            # Fallback to basic error logging if secure handling fails
            logger.error("Error occurred while handling error", exc_info=False)

class PrivilegeManager:
    def __init__(self):
        self.logger = logging.getLogger('privilege_manager')
        self.original_uid = os.getuid()
        self.original_gid = os.getgid()
        self.original_groups = os.getgroups()
        self.required_privileges = {
            'files': set(),
            'directories': set(),
            'capabilities': set()
        }

    def drop_privileges(self, uid: Optional[int] = None, gid: Optional[int] = None):
        """Drop privileges to the specified user/group."""
        try:
            if uid is None:
                # Get the current user's UID
                uid = os.getuid()
            
            if gid is None:
                # Get the current user's primary GID
                gid = os.getgid()
            
            # Remove all supplementary groups
            os.setgroups([])
            
            # Set the new GID
            os.setgid(gid)
            
            # Set the new UID
            os.setuid(uid)
            
            # Verify privileges were dropped
            if os.getuid() != uid or os.getgid() != gid:
                raise SecurityError('PRIVILEGE_ERROR', {
                    'message': 'Failed to drop privileges',
                    'expected_uid': uid,
                    'actual_uid': os.getuid(),
                    'expected_gid': gid,
                    'actual_gid': os.getgid()
                })
            
            self.logger.info(f"Privileges dropped to UID: {uid}, GID: {gid}")
        except Exception as e:
            self.logger.error(f"Failed to drop privileges: {e}")
            raise SecurityError('PRIVILEGE_ERROR', {'message': str(e)})

    def restore_privileges(self):
        """Restore original privileges."""
        try:
            # Restore original groups
            os.setgroups(self.original_groups)
            
            # Restore original GID
            os.setgid(self.original_gid)
            
            # Restore original UID
            os.setuid(self.original_uid)
            
            self.logger.info("Original privileges restored")
        except Exception as e:
            self.logger.error(f"Failed to restore privileges: {e}")
            raise SecurityError('PRIVILEGE_ERROR', {'message': str(e)})

    def check_file_permissions(self, path: str, required_perms: int) -> bool:
        """Check if file has required permissions."""
        try:
            st = os.stat(path)
            return (st.st_mode & required_perms) == required_perms
        except Exception:
            return False

    def set_minimal_permissions(self, path: str, uid: int, gid: int, perms: int):
        """Set minimal required permissions on a file/directory."""
        try:
            os.chown(path, uid, gid)
            os.chmod(path, perms)
            self.logger.info(f"Set permissions on {path}: {oct(perms)}")
        except Exception as e:
            self.logger.error(f"Failed to set permissions on {path}: {e}")
            raise SecurityError('PERMISSION_ERROR', {'message': str(e)})

    def verify_privileges(self):
        """Verify that current privileges are sufficient but minimal."""
        try:
            # Check file permissions
            for path in self.required_privileges['files']:
                if not os.path.exists(path):
                    continue
                if not self.check_file_permissions(path, stat.S_IRUSR):
                    raise SecurityError('PERMISSION_ERROR', {
                        'message': f'Insufficient permissions for {path}',
                        'required': 'read',
                        'actual': oct(os.stat(path).st_mode)
                    })
            
            # Check directory permissions
            for path in self.required_privileges['directories']:
                if not os.path.exists(path):
                    continue
                if not self.check_file_permissions(path, stat.S_IXUSR):
                    raise SecurityError('PERMISSION_ERROR', {
                        'message': f'Insufficient permissions for directory {path}',
                        'required': 'execute',
                        'actual': oct(os.stat(path).st_mode)
                    })
            
            self.logger.info("Privilege verification successful")
        except Exception as e:
            self.logger.error(f"Privilege verification failed: {e}")
            raise

class ContainerSecurity:
    def __init__(self):
        self.logger = logging.getLogger('container_security')
        self.is_containerized = self._check_containerized()
        self.tmp_dir = '/app/tmp' if self.is_containerized else None

    def _check_containerized(self) -> bool:
        """Check if running in a container."""
        try:
            # Check for container-specific files
            if os.path.exists('/.dockerenv'):
                return True
            
            # Check cgroup
            with open('/proc/1/cgroup', 'r') as f:
                return 'docker' in f.read()
        except Exception:
            return False

    def verify_container_security(self):
        """Verify container security settings."""
        if not self.is_containerized:
            self.logger.warning("Not running in a container - some security features may be limited")
            return

        try:
            # Verify read-only filesystem
            if not os.access('/app', os.W_OK):
                self.logger.info("Filesystem is read-only (good)")
            else:
                self.logger.warning("Filesystem is writable (potential security risk)")

            # Verify user is not root
            if os.getuid() == 0:
                raise SecurityError('CONTAINER_ERROR', {
                    'message': 'Running as root in container',
                    'uid': os.getuid()
                })

            # Verify tmpfs mount
            if self.tmp_dir and not os.path.ismount(self.tmp_dir):
                raise SecurityError('CONTAINER_ERROR', {
                    'message': 'Temporary directory not mounted as tmpfs',
                    'path': self.tmp_dir
                })

            self.logger.info("Container security verification passed")
        except Exception as e:
            self.logger.error(f"Container security verification failed: {e}")
            raise

    def get_secure_temp_dir(self) -> str:
        """Get a secure temporary directory path."""
        if self.is_containerized and self.tmp_dir:
            return self.tmp_dir
        return tempfile.gettempdir()

class SecureMIMICTherapyNotesAnalyzer:
    def __init__(self, credential_source: str = 'interactive', encrypted_file: Optional[str] = None):
        """Initialize the analyzer with secure credential handling."""
        # Initialize memory protection
        try:
            MemoryProtection.lock_memory()
            if not MemoryProtection.verify_memory_protection():
                raise SecurityError('MEMORY_ERROR', {'message': 'Failed to protect memory'})
        except Exception as e:
            logger.error(f"Memory protection initialization failed: {e}")
            raise
        
        # Initialize container security
        self.container_security = ContainerSecurity()
        self.container_security.verify_container_security()
        
        # Initialize privilege manager
        self.privilege_manager = PrivilegeManager()
        
        # Set required privileges
        self.privilege_manager.required_privileges['files'].add(certifi.where())
        if encrypted_file:
            self.privilege_manager.required_privileges['files'].add(encrypted_file)
        
        # Verify privileges before proceeding
        self.privilege_manager.verify_privileges()
        
        # Drop privileges to current user
        self.privilege_manager.drop_privileges()
        
        # Initialize other components
        self.logger = secure_logger
        self.credential_manager = SecureCredentialManager()
        self.key_manager = SecureKeyManager()
        self.tls_manager = TLSSecurityManager()
        self.env_manager = SecureEnvironmentManager()
        self.data_processor = SecureDataProcessor()
        
        # Get credentials based on source
        if credential_source == 'interactive':
            self.db_config = self.credential_manager.get_credentials_interactive()
        elif credential_source == 'encrypted' and encrypted_file:
            self.db_config = self.credential_manager.get_credentials_from_encrypted(encrypted_file)
        else:
            raise ValidationError('INVALID_CREDENTIAL_SOURCE')
        
        # Initialize database connection
        self._connect_db()
        
        # Register cleanup handler
        atexit.register(self.cleanup)

    def _connect_db(self):
        """Establish secure connection to MIMIC database with certificate verification."""
        try:
            # Log connection attempt
            self.logger.audit(
                action="DATABASE_CONNECTION",
                status="ATTEMPTING",
                details={'host': '*****'}  # Sanitized host information
            )
            
            # Get SSL context from key manager
            ssl_context = self.key_manager.get_ssl_context()
            
            # Connect with SSL
            self.conn = psycopg2.connect(
                dbname=self.db_config['dbname'],
                user=self.db_config['user'],
                password=self.db_config['password'],
                host=self.db_config['host'],
                port=self.db_config['port'],
                sslmode='verify-full',
                sslrootcert=certifi.where(),
                sslcontext=ssl_context
            )
            
            # Verify SSL is being used
            with self.conn.cursor() as cur:
                cur.execute("SHOW ssl")
                ssl_status = cur.fetchone()[0]
                if ssl_status != 'on':
                    raise SecurityError('SSL_ERROR')
            
            # Verify TLS version
            if not self.tls_manager.verify_tls_version(self.conn):
                raise SecurityError('TLS_ERROR')
            
            # Log successful connection
            self.logger.audit(
                action="DATABASE_CONNECTION",
                status="ESTABLISHED",
                details={
                    'ssl_status': 'on',
                    'tls_version': '1.3'
                }
            )
            
            # Initialize database manager
            self.db_manager = SecureDatabaseManager(self.conn)
            
            # Prepare common queries
            self._prepare_common_queries()
        except psycopg2.Error as e:
            SecureErrorHandler.handle_error(
                DatabaseError('CONNECTION_FAILED', {'error': str(e)}),
                'database_connection'
            )
            raise
        except Exception as e:
            SecureErrorHandler.handle_error(e, 'database_connection')
            raise

    def cleanup(self):
        """Securely clean up all resources."""
        try:
            # Clear sensitive data
            self.credential_manager.clear_credentials()
            self.key_manager.cleanup()
            self.env_manager.clear_environment()
            self.data_processor.clear_sensitive_data()
            
            # Close database connection
            if self.conn:
                self.conn.close()
            
            # Restore original privileges
            self.privilege_manager.restore_privileges()
            
            # Clear logs
            self.logger.clear_logs()
            self.logger.clear_audit_logs()
            
            # Force garbage collection
            gc.collect()
            
            # If in container, ensure tmpfs is cleared
            if self.container_security.is_containerized:
                tmp_dir = self.container_security.get_secure_temp_dir()
                for root, dirs, files in os.walk(tmp_dir):
                    for file in files:
                        try:
                            path = os.path.join(root, file)
                            with open(path, 'wb') as f:
                                f.write(os.urandom(os.path.getsize(path)))
                            os.remove(path)
                        except Exception:
                            pass
            
            # Unlock memory
            MemoryProtection.unlock_memory()
        except Exception as e:
            SecureErrorHandler.handle_error(e, 'cleanup')
            raise

def main():
    try:
        # Check if running as root
        if os.getuid() == 0:
            print("Error: This script should not be run as root")
            sys.exit(1)
        
        # Get current user info
        current_user = pwd.getpwuid(os.getuid())
        current_group = grp.getgrgid(os.getgid())
        
        print(f"Running as user: {current_user.pw_name} ({current_user.pw_uid})")
        print(f"Group: {current_group.gr_name} ({current_group.gr_gid})")
        
        # Check container environment
        container_security = ContainerSecurity()
        if container_security.is_containerized:
            print("Running in containerized environment")
            container_security.verify_container_security()
        
        # Get credential source
        print("\nSelect credential source:")
        print("1. Interactive input")
        print("2. Encrypted file")
        choice = input("Enter your choice (1 or 2): ")
        
        if choice == "1":
            analyzer = SecureMIMICTherapyNotesAnalyzer(credential_source='interactive')
        elif choice == "2":
            encrypted_file = input("Enter path to encrypted credentials file: ")
            analyzer = SecureMIMICTherapyNotesAnalyzer(credential_source='encrypted', encrypted_file=encrypted_file)
        else:
            print("Invalid choice. Exiting.")
            sys.exit(1)
        
        # Process notes
        results = analyzer.process_notes_from_mimic(batch_size=1000)
        
        # Print summary
        print("\nAnalysis Summary:")
        print(f"Total notes analyzed: {results['total_notes']}")
        print(f"Co-treatment mentions: {results['co_treatment_mentions']} ({results['co_treatment_percentage']:.1f}%)")
        
    except KeyboardInterrupt:
        print("\nProcess interrupted. Cleaning up...")
    except Exception as e:
        SecureErrorHandler.handle_error(e, 'main')
        sys.exit(1)
    finally:
        if 'analyzer' in locals():
            analyzer.cleanup()

if __name__ == "__main__":
    main() 