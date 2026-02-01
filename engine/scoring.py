from logger import setup_logger

logger = setup_logger(__name__)


class ScoringEngine:
    SECTIONS = {
        'reputation': 30,
        'integrity': 30,
        'version': 30,
        'vulnerabilities': 30,
        'antivirus': 20,
        'privileges': 30,
        'network': 30
    }
    
    TOTAL_POINTS = sum(SECTIONS.values())
    
    @staticmethod
    def calculate_reputation_score(signer_name, is_trusted=False):
        if not signer_name or signer_name == 'Unknown':
            return 10
        trusted = ['Microsoft', 'Adobe', 'Google', 'Apple', 'Intel', 'NVIDIA', 'Canonical', 'Mozilla', 'Oracle']
        for pub in trusted:
            if pub.lower() in str(signer_name).lower():
                return 30
        return 20
    
    @staticmethod
    def calculate_integrity_score(hash_value, is_signed, cert_valid):
        score = 0
        if hash_value:
            score += 10
        if is_signed:
            score += 10
        if cert_valid:
            score += 10
        return score
    
    @staticmethod
    def calculate_version_score(is_latest, is_supported):
        score = 0
        if is_supported:
            score += 20
        else:
            score += 5
        if is_latest:
            score += 10
        return score
    
    @staticmethod
    def calculate_vulnerability_score(cve_count, critical_count, high_count):
        if critical_count > 0:
            return 0
        if high_count > 0:
            return 10
        if cve_count == 0:
            return 30
        if cve_count <= 5:
            return 20
        return 15
    
    @staticmethod
    def calculate_antivirus_score(detection_count, total_engines):
        if detection_count == 0:
            return 20
        if detection_count <= 2:
            return 15
        if detection_count <= 5:
            return 10
        return 0
    
    @staticmethod
    def calculate_total_score(reputation_score, integrity_score, version_score, vulnerability_score, antivirus_score):
        return reputation_score + integrity_score + version_score + vulnerability_score + antivirus_score
    
    @staticmethod
    def get_verdict(total_score):
        percentage = (total_score / ScoringEngine.TOTAL_POINTS) * 100
        if total_score >= 160:
            return {'verdict': 'APPROVED', 'status': '✅ APPROVED', 'score': total_score, 'percentage': round(percentage, 1), 'recommendation': 'Safe to use. No major security concerns detected.'}
        elif total_score >= 105:
            return {'verdict': 'CONDITIONAL', 'status': '⚠️ CONDITIONAL', 'score': total_score, 'percentage': round(percentage, 1), 'recommendation': 'Use with caution. Review security concerns before deployment.'}
        else:
            return {'verdict': 'REJECTED', 'status': '❌ REJECTED', 'score': total_score, 'percentage': round(percentage, 1), 'recommendation': 'Do not use. Significant security risks detected.'}
    
    @staticmethod
    def generate_score_report(hash_value=None, signer_name=None, is_signed=False, cert_valid=False, is_latest=False, is_supported=False, cve_count=0, critical_count=0, high_count=0, detection_count=0, total_engines=70):
        reputation = ScoringEngine.calculate_reputation_score(signer_name)
        integrity = ScoringEngine.calculate_integrity_score(hash_value, is_signed, cert_valid)
        version = ScoringEngine.calculate_version_score(is_latest, is_supported)
        vulnerabilities = ScoringEngine.calculate_vulnerability_score(cve_count, critical_count, high_count)
        antivirus = ScoringEngine.calculate_antivirus_score(detection_count, total_engines)
        total_score = ScoringEngine.calculate_total_score(reputation, integrity, version, vulnerabilities, antivirus)
        verdict_info = ScoringEngine.get_verdict(total_score)
        
        return {
            'sections': {
                'reputation': {'score': reputation, 'max': 30, 'percentage': round((reputation / 30) * 100, 1)},
                'integrity': {'score': integrity, 'max': 30, 'percentage': round((integrity / 30) * 100, 1)},
                'version': {'score': version, 'max': 30, 'percentage': round((version / 30) * 100, 1)},
                'vulnerabilities': {'score': vulnerabilities, 'max': 30, 'percentage': round((vulnerabilities / 30) * 100, 1)},
                'antivirus': {'score': antivirus, 'max': 20, 'percentage': round((antivirus / 20) * 100, 1)}
            },
            'total': {'score': total_score, 'max': 200, 'percentage': round((total_score / 200) * 100, 1)},
            'verdict': verdict_info
        }
