import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509

class ServerCertificateManager:
    def __init__(self):
        self.server_cert_key = None
        self.server_cert = None
        self.cert_dir = Path(".config/server")
        self.cert_path = self.cert_dir / "cert.pem"
        self.key_path = self.cert_dir / "key.pem"
    def init(self, curve=None,CertificateManager = None, server_name="Quantum Chat Server"):
        """
        Initialize certificate manager - load existing cert or create new one

        Args:
            curve: Cryptographic curve to use (default: ec.SECP256R1())
            server_name: Name for the certificate subject
        Returns:
            x509.Certificate: The server certificate
        """
        if curve is None:
            curve = ec.SECP256R1()  # Default curve
        # Create folder if not have
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        # Check that certificate and private key are created ?
        if self.cert_path.exists() and self.key_path.exists():
            self._load_existing_cert()
            print("Certificate and key loaded from storage")
        else:
            self._create_new_cert(curve, server_name, CertificateManager)
            print(f"New certificate and key created and saved to {self.cert_dir}")
        return self.server_cert
    def _load_existing_cert(self):
        """Load existing certificate and key from files"""
        try:
            # Load private key from .config
            with open(self.key_path, "rb") as key_file:
                self.server_cert_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
            
            # Load certificate
            with open(self.cert_path, "rb") as cert_file:
                self.server_cert = x509.load_pem_x509_certificate(cert_file.read())
                
        except Exception as e:
            print(f"Error loading existing certificate: {e}")
            # If load failed, create new
            self._cleanup_corrupted_files()
            raise
    
    def _create_new_cert(self, curve, server_name,CertificateManager):
        """Create new certificate and key, then save to files"""
        # Build private key
        self.server_cert_key = ec.generate_private_key(curve)
        
        # Build certificate key
        self.server_cert = CertificateManager.generate_self_signed_cert(
            server_name, self.server_cert_key
        )
        
        # Save it
        self._save_cert_and_key()
    
    def _save_cert_and_key(self):
        """Save certificate and private key to files"""
        try:
            # Save private key to .config
            with open(self.key_path, "wb") as key_file:
                key_file.write(
                    self.server_cert_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )
            # Save certificate key to .config
            with open(self.cert_path, "wb") as cert_file:
                cert_file.write(
                    self.server_cert.public_bytes(serialization.Encoding.PEM)
                )
        except Exception as e:
            print(f"Error saving certificate: {e}")
            self._cleanup_corrupted_files()
            raise
    def _cleanup_corrupted_files(self):
        """Remove corrupted certificate files"""
        try:
            if self.cert_path.exists():
                self.cert_path.unlink()
            if self.key_path.exists():
                self.key_path.unlink()
        except Exception as e:
            print(f"Error cleaning up corrupted files: {e}")
    def get_certificate(self):
        """Get the current certificate"""
        return self.server_cert
    def get_private_key(self):
        """Get the current private key"""
        return self.server_cert_key
    def is_initialized(self):
        """Check if certificate manager is initialized"""
        return self.server_cert is not None and self.server_cert_key is not None


# Test
"""
# สร้าง instance
cert_manager = ServerCertificateManager()

# เรียกใช้ครั้งเดียว - จะ return certificate
server_cert = cert_manager.init()

# หรือใช้กับ parameters
server_cert = cert_manager.init(
    curve=ec.SECP384R1(), 
    server_name="My Custom Server"
)

# ใช้ certificate
print(f"Certificate subject: {server_cert.subject}")
"""
