from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import os
import json
from django.conf import settings
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class EncryptionService:
    """
    Service for handling encryption/decryption with key rotation and secure data handling
    """
    def __init__(self):
        """Initialize encryption service with current and previous keys"""
        try:
            self.current_key = settings.ENCRYPTION_KEY
        except AttributeError:
            logger.warning("ENCRYPTION_KEY not found in settings, using a temporary key for development")
            self.current_key = Fernet.generate_key().decode()
            
        try:
            self.previous_keys = settings.PREVIOUS_ENCRYPTION_KEYS
        except AttributeError:
            logger.warning("PREVIOUS_ENCRYPTION_KEYS not found in settings, using empty list")
            self.previous_keys = []
            
        self.fernet = Fernet(self.current_key.encode() if isinstance(self.current_key, str) else self.current_key)
        self.previous_fernets = [
            Fernet(key.encode() if isinstance(key, str) else key) 
            for key in self.previous_keys
        ]
    
    def encrypt_data(self, data, additional_key=None):
        """
        Encrypt data with optional additional key for extra security
        """
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
            elif not isinstance(data, str):
                data = str(data)
            
            # Convert to bytes
            data_bytes = data.encode()
            
            # If additional key provided, use it for extra encryption layer
            if additional_key:
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = b64encode(kdf.derive(additional_key.encode()))
                additional_fernet = Fernet(key)
                data_bytes = additional_fernet.encrypt(data_bytes)
            
            # Encrypt with main key
            encrypted_data = self.fernet.encrypt(data_bytes)
            return b64encode(encrypted_data).decode()
            
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise ValueError("Failed to encrypt data")
    
    def decrypt_data(self, encrypted_data, additional_key=None):
        """
        Decrypt data with optional additional key
        """
        try:
            # Decode from base64
            data_bytes = b64decode(encrypted_data)
            
            # Decrypt with main key
            decrypted_data = self.fernet.decrypt(data_bytes)
            
            # If additional key provided, decrypt second layer
            if additional_key:
                salt = decrypted_data[:16]
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = b64encode(kdf.derive(additional_key.encode()))
                additional_fernet = Fernet(key)
                decrypted_data = additional_fernet.decrypt(decrypted_data[16:])
            
            # Try to parse JSON if possible
            try:
                return json.loads(decrypted_data)
            except json.JSONDecodeError:
                return decrypted_data.decode()
                
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise ValueError("Failed to decrypt data")
    
    def rotate_key(self, new_key):
        """Rotate encryption key"""
        if not new_key:
            raise ValueError("New key cannot be empty")
            
        # Add current key to previous keys
        self.previous_keys.append(self.current_key)
        
        # Update current key
        self.current_key = new_key
        self.fernet = Fernet(new_key.encode() if isinstance(new_key, str) else new_key)
        
        # Update previous fernets
        self.previous_fernets = [
            Fernet(key.encode() if isinstance(key, str) else key) 
            for key in self.previous_keys
        ]
        
        logger.info("Encryption key rotated successfully")

    def reencrypt_with_current_key(self, encrypted_data):
        """Re-encrypt data with current key"""
        if encrypted_data is None:
            return None
            
        # First decrypt with any available key
        decrypted = self.decrypt_data(encrypted_data)
        
        # Then encrypt with current key
        return self.encrypt_data(decrypted)

# Global encryption service instance
encryption_service = EncryptionService() 