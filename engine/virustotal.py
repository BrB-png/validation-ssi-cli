import requests
import hashlib
from config import Config
from logger import setup_logger

logger = setup_logger(__name__)

class VirusTotalChecker:
    """Check file reputation on VirusTotal"""
    
    VT_API_URL = "https://www.virustotal.com/api/v3"
    
    @staticmethod
    def get_file_report_by_hash(file_hash):
        """
        Get file report from VirusTotal by SHA256 hash
        
        Args:
            file_hash: SHA256 hash of the file
            
        Returns:
            dict with keys: detections, engines, verdict, or None if error
        """
        try:
            if not Config.VT_API_KEY:
                logger.warning("VirusTotal API key not configured")
                return None
            
            # VirusTotal API endpoint for file hash lookup
            url = f"{VirusTotalChecker.VT_API_URL}/files/{file_hash}"
            
            headers = {
                "x-apikey": Config.VT_API_KEY
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                logger.warning(f"File hash not found in VirusTotal: {file_hash}")
                return None
            
            if response.status_code != 200:
                logger.error(f"VirusTotal API error: {response.status_code}")
                return None
            
            data = response.json()
            
            # Extract analysis results
            last_analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            result = {
                'file_hash': file_hash,
                'detection_count': last_analysis_stats.get('malicious', 0),
                'total_engines': sum(last_analysis_stats.values()),
                'engines_list': data.get('data', {}).get('attributes', {}).get('last_analysis_results', {}),
                'verdict': 'SUSPICIOUS' if last_analysis_stats.get('malicious', 0) > 0 else 'CLEAN'
            }
            
            logger.info(f"VirusTotal report retrieved for {file_hash}: {result['detection_count']} detections")
            return result
            
        except requests.exceptions.Timeout:
            logger.error(f"VirusTotal request timeout for hash: {file_hash}")
            return None
        except requests.exceptions.ConnectionError:
            logger.error(f"VirusTotal connection error")
            return None
        except Exception as e:
            logger.error(f"Error getting VirusTotal report: {e}")
            return None
    
    @staticmethod
    def get_file_report_by_upload(file_path):
        """
        Get file report by uploading file to VirusTotal
        
        Args:
            file_path: Full path to the file
            
        Returns:
            dict with analysis result, or None if error
        """
        try:
            if not Config.VT_API_KEY:
                logger.warning("VirusTotal API key not configured")
                return None
            
            url = f"{VirusTotalChecker.VT_API_URL}/files"
            
            headers = {
                "x-apikey": Config.VT_API_KEY
            }
            
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(url, headers=headers, files=files, timeout=30)
            
            if response.status_code != 200:
                logger.error(f"VirusTotal upload error: {response.status_code}")
                return None
            
            data = response.json()
            analysis_id = data.get('data', {}).get('id')
            
            logger.info(f"File uploaded to VirusTotal: {analysis_id}")
            
            # Return analysis ID for later polling
            return {
                'analysis_id': analysis_id,
                'status': 'QUEUED'
            }
            
        except Exception as e:
            logger.error(f"Error uploading file to VirusTotal: {e}")
            return None
    
    @staticmethod
    def get_analysis_result(analysis_id):
        """
        Get analysis result by analysis ID
        
        Args:
            analysis_id: Analysis ID returned from upload
            
        Returns:
            dict with analysis results, or None if not ready
        """
        try:
            if not Config.VT_API_KEY:
                logger.warning("VirusTotal API key not configured")
                return None
            
            url = f"{VirusTotalChecker.VT_API_URL}/analyses/{analysis_id}"
            
            headers = {
                "x-apikey": Config.VT_API_KEY
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                logger.error(f"VirusTotal analysis error: {response.status_code}")
                return None
            
            data = response.json()
            status = data.get('data', {}).get('attributes', {}).get('status')
            
            if status != 'completed':
                logger.info(f"Analysis still in progress: {status}")
                return None
            
            # Extract stats
            stats = data.get('data', {}).get('attributes', {}).get('stats', {})
            
            result = {
                'analysis_id': analysis_id,
                'status': status,
                'detection_count': stats.get('malicious', 0),
                'total_engines': sum(stats.values()),
                'verdict': 'SUSPICIOUS' if stats.get('malicious', 0) > 0 else 'CLEAN'
            }
            
            logger.info(f"Analysis completed: {result['detection_count']} detections")
            return result
            
        except Exception as e:
            logger.error(f"Error getting analysis result: {e}")
            return None
    
    @staticmethod
    def is_api_configured():
        """Check if VirusTotal API key is configured"""
        return bool(Config.VT_API_KEY)
    
    @staticmethod
    def get_verdict_score(detection_count, total_engines):
        """
        Calculate verdict and score based on detection count
        
        Args:
            detection_count: Number of engines detecting malware
            total_engines: Total number of engines
            
        Returns:
            dict with verdict and score
        """
        if detection_count == 0:
            return {
                'verdict': 'CLEAN',
                'score': 30,  # Max points for VirusTotal section
                'confidence': 'HIGH'
            }
        elif detection_count <= 3:
            return {
                'verdict': 'SUSPICIOUS',
                'score': 20,
                'confidence': 'MEDIUM'
            }
        else:
            return {
                'verdict': 'MALICIOUS',
                'score': 0,
                'confidence': 'HIGH'
            }
