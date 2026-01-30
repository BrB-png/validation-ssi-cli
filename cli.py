import click
import uuid
import os
from datetime import datetime
from config import Config
from database import Database
from logger import setup_logger
from engine.hash import FileHasher

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