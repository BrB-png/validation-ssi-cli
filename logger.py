import logging
import json
import os
from datetime import datetime

class StructuredFormatter(logging.Formatter):
    """Custom formatter to output logs as JSON"""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)

def setup_logger(name):
    """Setup structured JSON logger"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Create logs directory if it doesn't exist
    logs_dir = 'logs'
    os.makedirs(logs_dir, exist_ok=True)
    
    # File handler with JSON formatting
    log_file = os.path.join(logs_dir, 'validation.log')
    file_handler = logging.FileHandler(log_file)
    json_formatter = StructuredFormatter()
    file_handler.setFormatter(json_formatter)
    logger.addHandler(file_handler)
    
    # Console handler with standard formatting
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger