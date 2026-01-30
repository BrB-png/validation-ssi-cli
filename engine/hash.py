import hashlib
import os
from logger import setup_logger

logger = setup_logger(__name__)

class FileHasher:
    """Calculate and verify file hashes"""
    
    @staticmethod
    def calculate_sha256(file_path):
        """Calculate SHA256 hash of a file"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return None
            
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            hash_value = sha256_hash.hexdigest()
            logger.info(f"SHA256 calculated for {file_path}: {hash_value}")
            return hash_value
        except Exception as e:
            logger.error(f"Error calculating hash: {e}")
            return None
    
    @staticmethod
    def calculate_md5(file_path):
        """Calculate MD5 hash of a file"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return None
            
            md5_hash = hashlib.md5()
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    md5_hash.update(byte_block)
            
            hash_value = md5_hash.hexdigest()
            logger.info(f"MD5 calculated for {file_path}: {hash_value}")
            return hash_value
        except Exception as e:
            logger.error(f"Error calculating MD5: {e}")
            return None
    
    @staticmethod
    def verify_hash(file_path, expected_hash, hash_type='sha256'):
        """Verify file hash against expected value"""
        try:
            if hash_type.lower() == 'sha256':
                calculated = FileHasher.calculate_sha256(file_path)
            elif hash_type.lower() == 'md5':
                calculated = FileHasher.calculate_md5(file_path)
            else:
                logger.error(f"Unsupported hash type: {hash_type}")
                return False
            
            if calculated is None:
                return False
            
            match = calculated.lower() == expected_hash.lower()
            
            if match:
                logger.info(f"Hash verification successful for {file_path}")
            else:
                logger.warning(f"Hash mismatch for {file_path}")
            
            return match
        except Exception as e:
            logger.error(f"Error verifying hash: {e}")
            return False