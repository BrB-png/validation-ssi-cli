import click
import uuid
import os
from datetime import datetime
from config import Config
from database import Database
from logger import setup_logger
from engine.hash import FileHasher
from engine.signature import SignatureChecker
from engine.virustotal import VirusTotalChecker
from engine.cve import CVEChecker


logger = setup_logger(__name__)
db = Database()


def generate_validation_id():
    """Generate unique validation ID"""
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    unique_id = str(uuid.uuid4())[:8]
    return f"VAL-{timestamp}-{unique_id}"


@click.group()
def cli():
    """
    Automated Executable File Validation CLI
    
    Validates Windows .exe files for security, integrity, and vulnerabilities.
    """
    pass


@cli.command()
@click.option('--exe-path', required=True, type=click.Path(exists=True), 
              help='Path to the .exe file to validate')
@click.option('--software', required=True, help='Name of the software')
@click.option('--version', default='Unknown', help='Software version')
def validate(exe_path, software, version):
    """
    Validate an executable file
    
    Example: validate --exe-path "C:\\path\\to\\file.exe" --software "MyApp"
    """
    try:
        validation_id = generate_validation_id()
        click.echo(f"\n{'='*60}")
        click.echo(f"Validation ID: {validation_id}")
        click.echo(f"Software: {software}")
        click.echo(f"Version: {version}")
        click.echo(f"File: {exe_path}")
        click.echo(f"{'='*60}\n")
        
        # Calculate hash
        click.echo("📊 Calculating SHA256 hash...")
        sha256_hash = FileHasher.calculate_sha256(exe_path)
        
        if not sha256_hash:
            click.echo("❌ Error calculating hash")
            return
        
        click.echo(f"✅ Hash: {sha256_hash}\n")
        
        # Build results
        results = {
            'validation_id': validation_id,
            'software_name': software,
            'version': version,
            'file_path': exe_path,
            'hash_sha256': sha256_hash,
            'file_size': os.path.getsize(exe_path),
            'score': 0,
            'verdict': 'PENDING',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Save to database
        db.save_validation(validation_id, software, exe_path, results)
        click.echo(f"✅ Results saved to database\n")
        
        click.echo(f"{'='*60}")
        click.echo(f"Status: PENDING")
        click.echo(f"Next steps: Run other analysis stages")
        click.echo(f"{'='*60}\n")
        
    except Exception as e:
        logger.error(f"Validation error: {e}")
        click.echo(f"❌ Error: {e}")


@cli.command()
@click.option('--exe-path', required=True, type=click.Path(exists=True), 
              help='Path to the .exe file to check')
def signature(exe_path):
    """
    Check digital signature of an executable file
    
    Example: signature --exe-path "C:\\path\\to\\file.exe"
    """
    try:
        click.echo(f"\n{'='*60}")
        click.echo(f"Signature Check")
        click.echo(f"File: {exe_path}")
        click.echo(f"{'='*60}\n")
        
        # Get signature info
        sig_info = SignatureChecker.get_signature_info(exe_path)
        
        if sig_info is None:
            click.echo("❌ No signature information found\n")
            return
        
        # Display results
        click.echo(f"Status: {sig_info.get('Status', 'Unknown')}")
        click.echo(f"Signer: {sig_info.get('SignerCertificate', 'Not signed')}")
        click.echo(f"Issuer: {sig_info.get('Issuer', 'N/A')}")
        click.echo(f"Thumbprint: {sig_info.get('Thumbprint', 'N/A')}")
        click.echo(f"Valid From: {sig_info.get('NotBefore', 'N/A')}")
        click.echo(f"Valid Until: {sig_info.get('NotAfter', 'N/A')}")
        click.echo(f"TimeStamper: {sig_info.get('TimeStamperCertificate', 'N/A')}\n")
        
        # Check validity
        is_signed = SignatureChecker.is_signed(exe_path)
        is_valid = SignatureChecker.is_certificate_valid(exe_path)
        
        if is_signed:
            click.echo("✅ File is properly signed")
        else:
            click.echo("❌ File is not signed or signature is invalid")
        
        if is_valid:
            click.echo("✅ Certificate is valid")
        else:
            click.echo("⚠️ Certificate is expired or invalid")
        
        click.echo(f"{'='*60}\n")
        
        logger.info(f"Signature check completed for {exe_path}")
        
    except Exception as e:
        logger.error(f"Signature check error: {e}")
        click.echo(f"❌ Error: {e}")


@cli.command()
@click.option('--exe-path', required=True, type=click.Path(exists=True), 
              help='Path to the .exe file to scan')
@click.option('--file-hash', default=None,
              help='SHA256 hash (if not provided, will be calculated)')
def virustotal(exe_path, file_hash):
    """
    Scan file on VirusTotal
    
    Example: virustotal --exe-path "C:\\path\\to\\file.exe"
    """
    try:
        # Check if API key is configured
        if not VirusTotalChecker.is_api_configured():
            click.echo("\n❌ VirusTotal API key not configured")
            click.echo("Please add VT_API_KEY to .env file\n")
            logger.warning("VirusTotal API key not configured")
            return
        
        click.echo(f"\n{'='*60}")
        click.echo(f"VirusTotal Scan")
        click.echo(f"File: {exe_path}")
        click.echo(f"{'='*60}\n")
        
        # Get or calculate hash
        if not file_hash:
            click.echo("📊 Calculating SHA256 hash...")
            file_hash = FileHasher.calculate_sha256(exe_path)
            if not file_hash:
                click.echo("❌ Error calculating hash\n")
                return
            click.echo(f"✅ Hash: {file_hash}\n")
        
        # Get VirusTotal report
        click.echo("🔍 Querying VirusTotal...")
        vt_result = VirusTotalChecker.get_file_report_by_hash(file_hash)
        
        if vt_result is None:
            click.echo("⚠️ File not found in VirusTotal database")
            click.echo("(File may be new or clean)\n")
            vt_result = {
                'detection_count': 0,
                'total_engines': 0,
                'verdict': 'UNKNOWN'
            }
        
        # Display results
        click.echo(f"Detection Count: {vt_result.get('detection_count', 0)}/{vt_result.get('total_engines', 70)}")
        click.echo(f"Verdict: {vt_result.get('verdict', 'UNKNOWN')}\n")
        
        # Get verdict score
        verdict_info = VirusTotalChecker.get_verdict_score(
            vt_result.get('detection_count', 0),
            vt_result.get('total_engines', 70)
        )
        
        click.echo(f"Score: {verdict_info['score']}/30")
        click.echo(f"Confidence: {verdict_info['confidence']}")
        
        # Display status
        if vt_result.get('detection_count', 0) == 0:
            click.echo("\n✅ No malware detected")
        elif vt_result.get('detection_count', 0) <= 3:
            click.echo("\n⚠️ Low detection rate (possibly false positive)")
        else:
            click.echo("\n❌ Multiple engines detected malware")
        
        click.echo(f"{'='*60}\n")
        
        logger.info(f"VirusTotal scan completed for {exe_path}")
        
    except Exception as e:
        logger.error(f"VirusTotal scan error: {e}")
        click.echo(f"❌ Error: {e}")


@cli.command()
@click.option('--software', required=True, help='Software name to search')
@click.option('--version', default=None, help='Software version (optional)')
@click.option('--cve-id', default=None, help='Specific CVE ID to lookup')
def cve(software, version, cve_id):
    """
    Search for CVE vulnerabilities
    
    Example: cve --software "7-Zip" --version "25.01"
    Example: cve --cve-id "CVE-2021-12345"
    """
    try:
        click.echo(f"\n{'='*60}")
        click.echo(f"CVE/Vulnerability Search")
        click.echo(f"{'='*60}\n")
        
        # If specific CVE ID provided, get details
        if cve_id:
            click.echo(f"Searching for CVE: {cve_id}\n")
            cve_details = CVEChecker.get_cve_by_id(cve_id)
            
            if cve_details is None:
                click.echo("❌ CVE not found\n")
                return
            
            click.echo(f"CVE ID: {cve_details.get('cve_id')}")
            click.echo(f"Severity: {cve_details.get('severity')}")
            click.echo(f"CVSS Score: {cve_details.get('cvss_score')}")
            click.echo(f"Published: {cve_details.get('published_date')}")
            click.echo(f"Description: {cve_details.get('description')}\n")
            
        else:
            # Search by software name
            search_term = software
            if version:
                search_term = f"{software} {version}"
            
            click.echo(f"Searching for: {search_term}\n")
            cve_results = CVEChecker.search_cve_by_software(software, version)
            
            if cve_results.get('error'):
                click.echo(f"⚠️ Error: {cve_results.get('error')}\n")
                return
            
            if not cve_results.get('found'):
                click.echo("✅ No CVE vulnerabilities found\n")
            else:
                click.echo(f"Found {cve_results.get('count')} CVE(s):\n")
                
                for cve in cve_results.get('cves', []):
                    click.echo(f"CVE: {cve.get('cve_id')}")
                    click.echo(f"Severity: {cve.get('severity')}")
                    click.echo(f"Description: {cve.get('description')[:100]}...\n")
                
                # Calculate score
                critical_count = len([c for c in cve_results.get('cves', []) if 'CRITICAL' in c.get('severity', '')])
                high_count = len([c for c in cve_results.get('cves', []) if 'HIGH' in c.get('severity', '')])
                
                score_info = CVEChecker.calculate_cve_score(
                    cve_results.get('count', 0),
                    critical_count,
                    high_count
                )
                
                click.echo(f"Verdict: {score_info['verdict']}")
                click.echo(f"Score: {score_info['score']}/30")
                click.echo(f"Confidence: {score_info['confidence']}\n")
        
        click.echo(f"{'='*60}\n")
        logger.info(f"CVE search completed for {software}")
        
    except Exception as e:
        logger.error(f"CVE search error: {e}")
        click.echo(f"❌ Error: {e}")


@cli.command()
@click.option('--limit', default=10, help='Number of validations to show')
def history(limit):
    """
    Show validation history
    
    Example: history --limit 20
    """
    try:
        validations = db.get_all_validations(limit=limit)
        
        if not validations:
            click.echo("No validations found")
            return
        
        click.echo(f"\n{'='*80}")
        click.echo(f"Last {len(validations)} validations:")
        click.echo(f"{'='*80}\n")
        
        for val in validations:
            click.echo(f"ID: {val['id']}")
            click.echo(f"Software: {val['software_name']}")
            click.echo(f"Hash: {val['hash_sha256']}")
            click.echo(f"Verdict: {val['verdict']}")
            click.echo(f"Score: {val['score']}/200")
            click.echo(f"Created: {val['created_at']}")
            click.echo("-" * 80)
        
    except Exception as e:
        logger.error(f"History error: {e}")
        click.echo(f"❌ Error: {e}")


@cli.command()
@click.option('--validation-id', required=True, help='Validation ID to retrieve')
def details(validation_id):
    """
    Show details of a specific validation
    
    Example: details --validation-id VAL-20260130XXXXXX-XXXXXXXX
    """
    try:
        validation = db.get_validation(validation_id)
        
        if not validation:
            click.echo(f"Validation {validation_id} not found")
            return
        
        click.echo(f"\n{'='*80}")
        click.echo(f"Validation Details: {validation_id}")
        click.echo(f"{'='*80}\n")
        
        click.echo(f"Software: {validation['software_name']}")
        click.echo(f"File: {validation['file_path']}")
        click.echo(f"Version: {validation['version']}")
        click.echo(f"Hash: {validation['hash_sha256']}")
        click.echo(f"Score: {validation['score']}/200")
        click.echo(f"Verdict: {validation['verdict']}")
        click.echo(f"Created: {validation['created_at']}")
        click.echo(f"Updated: {validation['updated_at']}")
        
        if validation['results']:
            click.echo(f"\n{'='*80}")
            click.echo("Full Results:")
            click.echo(f"{'='*80}\n")
            click.echo(validation['results'])
        
    except Exception as e:
        logger.error(f"Details error: {e}")
        click.echo(f"❌ Error: {e}")


if __name__ == '__main__':
    cli()
