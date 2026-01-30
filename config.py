import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv('.env')

class Config:
    """Configuration management for validation CLI"""
    
    # API Keys
    VT_API_KEY = os.getenv('VT_API_KEY', '')
    NVD_API_KEY = os.getenv('NVD_API_KEY', '')
    
    # Database and logging paths
    DB_PATH = os.getenv('DB_PATH', 'validations.db')
    LOG_PATH = os.getenv('LOG_PATH', 'logs/')
    
    # Create directories if they don't exist
    @staticmethod
    def init_directories():
        """Initialize required directories"""
        os.makedirs(Config.LOG_PATH, exist_ok=True)
        os.makedirs('reports', exist_ok=True)
        os.makedirs('config', exist_ok=True)

# Initialize directories on import
Config.init_directories()