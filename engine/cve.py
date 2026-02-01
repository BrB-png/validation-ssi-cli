import requests
from config import Config
from logger import setup_logger

logger = setup_logger(__name__)

class CVEChecker:
    """Search for CVE vulnerabilities in NVD database"""
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    
    @staticmethod
    def search_cve_by_software(software_name, version=None):
        """Search CVE by software name and version"""
        try:
            search_query = software_name
            if version:
                search_query = f"{software_name} {version}"
            
            params = {
                'keyword': search_query
            }
            
            response = requests.get(CVEChecker.NVD_API_URL, params=params, timeout=10)
            
            if response.status_code != 200:
                logger.error(f"NVD API error: {response.status_code}")
                return {
                    'found': False,
                    'count': 0,
                    'cves': []
                }
            
            data = response.json()
            result_count = data.get('totalResults', 0)
            
            cves = []
            if result_count > 0:
                for cve_item in data.get('result', {}).get('CVE_Items', []):
                    cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                    cvss_score = cve_item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'UNKNOWN')
                    description = cve_item.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', '')
                    
                    cves.append({
                        'cve_id': cve_id,
                        'severity': cvss_score,
                        'description': description
                    })
            
            result = {
                'found': result_count > 0,
                'count': result_count,
                'cves': cves[:10]
            }
            
            logger.info(f"CVE search completed for '{search_query}': {result_count} results")
            return result
            
        except requests.exceptions.Timeout:
            logger.error(f"NVD API timeout for query: {software_name}")
            return {
                'found': False,
                'count': 0,
                'cves': [],
                'error': 'API timeout'
            }
        except requests.exceptions.ConnectionError:
            logger.error(f"NVD API connection error")
            return {
                'found': False,
                'count': 0,
                'cves': [],
                'error': 'Connection error'
            }
        except Exception as e:
            logger.error(f"Error searching CVE: {e}")
            return {
                'found': False,
                'count': 0,
                'cves': [],
                'error': str(e)
            }
    
    @staticmethod
    def get_cve_by_id(cve_id):
        """Get detailed CVE information by CVE ID"""
        try:
            params = {
                'keyword': cve_id
            }
            
            response = requests.get(CVEChecker.NVD_API_URL, params=params, timeout=10)
            
            if response.status_code != 200:
                logger.error(f"NVD API error: {response.status_code}")
                return None
            
            data = response.json()
            
            if data.get('totalResults', 0) == 0:
                logger.warning(f"CVE not found: {cve_id}")
                return None
            
            cve_item = data.get('result', {}).get('CVE_Items', [{}])[0]
            
            cve_details = {
                'cve_id': cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID'),
                'description': cve_item.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', ''),
                'severity': cve_item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'UNKNOWN'),
                'cvss_score': cve_item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 0),
                'published_date': cve_item.get('publishedDate', 'Unknown'),
                'last_modified': cve_item.get('lastModifiedDate', 'Unknown')
            }
            
            logger.info(f"CVE details retrieved: {cve_id}")
            return cve_details
            
        except Exception as e:
            logger.error(f"Error getting CVE details: {e}")
            return None
    
    @staticmethod
    def calculate_cve_score(cve_count, critical_count=0, high_count=0):
        """Calculate score based on CVE findings"""
        if cve_count == 0:
            return {
                'verdict': 'CLEAN',
                'score': 30,
                'confidence': 'HIGH'
            }
        elif critical_count > 0:
            return {
                'verdict': 'CRITICAL',
                'score': 0,
                'confidence': 'HIGH'
            }
        elif high_count > 0:
            return {
                'verdict': 'HIGH_RISK',
                'score': 10,
                'confidence': 'HIGH'
            }
        elif cve_count <= 5:
            return {
                'verdict': 'MEDIUM_RISK',
                'score': 20,
                'confidence': 'MEDIUM'
            }
        else:
            return {
                'verdict': 'LOW_RISK',
                'score': 25,
                'confidence': 'LOW'
            }
