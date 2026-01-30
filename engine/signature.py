import subprocess
import json
import os
from datetime import datetime
from logger import setup_logger


logger = setup_logger(__name__)


class SignatureChecker:
    """Check Windows digital signatures on executable files"""
    
    @staticmethod
    def get_signature_info(file_path):
        """Get signature information from a Windows executable file"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return None
            
            ps_command = f"""
            $cert = Get-AuthenticodeSignature -FilePath '{file_path}'
            $result = @{{
                Status = $cert.Status.ToString()
                SignerCertificate = $cert.SignerCertificate.Subject
                Issuer = $cert.SignerCertificate.Issuer
                Thumbprint = $cert.SignerCertificate.Thumbprint
                NotBefore = $cert.SignerCertificate.NotBefore.ToString()
                NotAfter = $cert.SignerCertificate.NotAfter.ToString()
                TimeStamperCertificate = $cert.TimeStamperCertificate.Subject
                SignatureType = $cert.SignatureType.ToString()
            }}
            $result | ConvertTo-Json
            """
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.warning(f"PowerShell error for {file_path}: {result.stderr}")
                return None
            
            signature_data = json.loads(result.stdout)
            logger.info(f"Signature retrieved for {file_path}: Status={signature_data.get('Status')}")
            return signature_data
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}")
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"PowerShell command timeout for {file_path}")
            return None
        except Exception as e:
            logger.error(f"Error getting signature: {e}")
            return None
    
    @staticmethod
    def is_signed(file_path):
        """Check if file has a valid digital signature"""
        try:
            sig_info = SignatureChecker.get_signature_info(file_path)
            
            if sig_info is None:
                return False
            
            status = sig_info.get('Status', '').lower()
            return status == 'valid'
            
        except Exception as e:
            logger.error(f"Error checking signature validity: {e}")
            return False
    
    @staticmethod
    def get_signer_name(file_path):
        """Extract signer name from certificate subject"""
        try:
            sig_info = SignatureChecker.get_signature_info(file_path)
            
            if sig_info is None:
                return None
            
            signer_subject = sig_info.get('SignerCertificate', '')
            
            for part in signer_subject.split(','):
                part = part.strip()
                if part.startswith('CN='):
                    signer_name = part.replace('CN=', '')
                    logger.info(f"Signer name extracted: {signer_name}")
                    return signer_name
            
            return signer_subject if signer_subject else None
            
        except Exception as e:
            logger.error(f"Error extracting signer name: {e}")
            return None
    
    @staticmethod
    def is_certificate_valid(file_path):
        """Check if certificate is not expired"""
        try:
            sig_info = SignatureChecker.get_signature_info(file_path)
            
            if sig_info is None:
                return False
            
            not_after_str = sig_info.get('NotAfter', '')
            
            if not not_after_str:
                return False
            
            # Parse date in format: "17/06/2026 20:11:44"
            try:
                not_after = datetime.strptime(not_after_str, '%d/%m/%Y %H:%M:%S')
            except ValueError:
                # Try ISO format if first format fails
                try:
                    not_after = datetime.fromisoformat(not_after_str)
                except ValueError:
                    logger.error(f"Unable to parse date: {not_after_str}")
                    return False
            
            current_time = datetime.now()
            is_valid = current_time < not_after
            
            if is_valid:
                logger.info(f"Certificate valid until {not_after_str}")
            else:
                logger.warning(f"Certificate expired on {not_after_str}")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Error checking certificate validity: {e}")
            return False
