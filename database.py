import sqlite3
import json
import os
from datetime import datetime
from config import Config
from logger import setup_logger

logger = setup_logger(__name__)

class Database:
    """SQLite database manager for validation results"""
    
    def __init__(self):
        self.db_path = Config.DB_PATH
        self.conn = None
        self.connect()
        self.init_tables()
    
    def connect(self):
        """Connect to SQLite database"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            logger.info(f"Connected to database: {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            raise
    
    def init_tables(self):
        """Initialize database tables"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS validations (
                id TEXT PRIMARY KEY,
                software_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                hash_sha256 TEXT,
                signature_status TEXT,
                signature_signer TEXT,
                version TEXT,
                score INTEGER,
                verdict TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                results JSON
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                validation_id TEXT NOT NULL,
                cve_id TEXT,
                cvss_score REAL,
                severity TEXT,
                patched INTEGER,
                FOREIGN KEY (validation_id) REFERENCES validations(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS virustotal_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                validation_id TEXT NOT NULL,
                detection_count INTEGER,
                total_engines INTEGER,
                scan_date TIMESTAMP,
                FOREIGN KEY (validation_id) REFERENCES validations(id)
            )
        ''')
        
        self.conn.commit()
        logger.info("Database tables initialized")
    
    def save_validation(self, validation_id, software_name, file_path, results):
        """Save validation results to database"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO validations 
                (id, software_name, file_path, hash_sha256, score, verdict, results, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                validation_id,
                software_name,
                file_path,
                results.get('hash_sha256'),
                results.get('score', 0),
                results.get('verdict', 'PENDING'),
                json.dumps(results),
                datetime.utcnow().isoformat()
            ))
            
            self.conn.commit()
            logger.info(f"Validation saved: {validation_id}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Error saving validation: {e}")
            return False
    
    def get_validation(self, validation_id):
        """Retrieve validation by ID"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM validations WHERE id = ?', (validation_id,))
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
        except sqlite3.Error as e:
            logger.error(f"Error retrieving validation: {e}")
            return None
    
    def get_all_validations(self, limit=100):
        """Retrieve all validations"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                'SELECT * FROM validations ORDER BY created_at DESC LIMIT ?',
                (limit,)
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error(f"Error retrieving validations: {e}")
            return []
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")