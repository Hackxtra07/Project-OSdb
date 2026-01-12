"""
Advanced Encryption Module with multiple algorithms and key management
"""

import base64
import hashlib
import secrets
import string
from typing import Tuple, Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import logging

logger = logging.getLogger(__name__)

class EncryptionManager:
    """Advanced encryption with multiple algorithms and key management"""
    
    def __init__(self):
        self.supported_algorithms = {
            'fernet': self._encrypt_fernet,
            'aes_gcm': self._encrypt_aes_gcm,
            'chacha20': self._encrypt_chacha20
        }
        self.default_algorithm = 'aes_gcm'
        self.key_lengths = {
            'fernet': 32,
            'aes_gcm': 32,  # AES-256
            'chacha20': 32   # ChaCha20 with 256-bit key
        }
    
    
    def generate_salt(self, length: int = 32) -> bytes:
        """Generate random salt"""
        return secrets.token_bytes(length)

    def hash_password(self, password: str, salt: bytes = None) -> str:
        """Hash password for storage"""
        # Note: auth_window currently calls this without salt during login.
        # For compatibility with current auth flow, we use SHA-256.
        # In a future update, auth_window should be refactored to fetch salt first,
        # then use Scrypt/Argon2.
        sha256 = hashlib.sha256()
        sha256.update(password.encode('utf-8'))
        if salt:
            sha256.update(salt)
        return sha256.hexdigest()

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        key, _ = self.generate_key(password, salt)
        return key

    def generate_key(self, password: str, salt: bytes = None, 
                    algorithm: str = 'scrypt', iterations: int = 310000) -> Tuple[bytes, bytes]:
        """Generate encryption key from password"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        if algorithm == 'scrypt':
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,  # CPU/memory cost parameter
                r=8,      # Block size
                p=1       # Parallelization parameter
            )
            key = kdf.derive(password.encode())
        
        elif algorithm == 'pbkdf2':
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=iterations
            )
            key = kdf.derive(password.encode())
        
        else:
            raise ValueError(f"Unsupported KDF algorithm: {algorithm}")
        
        return key, salt
    
    def encrypt_data(self, data: Union[str, bytes], key: bytes, 
                    algorithm: str = None) -> str:
        """Encrypt data using specified algorithm"""
        if algorithm is None:
            algorithm = self.default_algorithm
        
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            encrypted_data = self.supported_algorithms[algorithm](data, key)
            return base64.b64encode(encrypted_data).decode('ascii')
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: str, key: bytes, 
                    algorithm: str = None) -> str:
        """Decrypt data using specified algorithm"""
        if algorithm is None:
            algorithm = self.default_algorithm
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            if algorithm == 'fernet':
                fernet = Fernet(base64.urlsafe_b64encode(key[:32]))
                decrypted = fernet.decrypt(encrypted_bytes)
            
            elif algorithm == 'aes_gcm':
                # Extract nonce and ciphertext
                nonce = encrypted_bytes[:12]
                ciphertext = encrypted_bytes[12:-16]
                tag = encrypted_bytes[-16:]
                
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.GCM(nonce, tag)
                )
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            elif algorithm == 'chacha20':
                # Extract nonce and ciphertext
                nonce = encrypted_bytes[:12]
                ciphertext = encrypted_bytes[12:]
                
                cipher = Cipher(
                    algorithms.ChaCha20(key, nonce),
                    mode=None
                )
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(ciphertext)
            
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            return decrypted.decode('utf-8')
        
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def _encrypt_fernet(self, data: bytes, key: bytes) -> bytes:
        """Encrypt using Fernet (AES-128-CBC)"""
        fernet = Fernet(base64.urlsafe_b64encode(key[:32]))
        return fernet.encrypt(data)
    
    def _encrypt_aes_gcm(self, data: bytes, key: bytes) -> bytes:
        """Encrypt using AES-GCM (authenticated encryption)"""
        # Generate random nonce
        nonce = secrets.token_bytes(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce)
        )
        encryptor = cipher.encryptor()
        
        # Encrypt data
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return nonce + ciphertext + tag
        return nonce + ciphertext + encryptor.tag
    
    def _encrypt_chacha20(self, data: bytes, key: bytes) -> bytes:
        """Encrypt using ChaCha20-Poly1305"""
        # Generate random nonce
        nonce = secrets.token_bytes(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            mode=None
        )
        encryptor = cipher.encryptor()
        
        # Encrypt data
        ciphertext = encryptor.update(data)
        
        # Return nonce + ciphertext
        return nonce + ciphertext
    
    def encrypt_file(self, input_path: str, output_path: str, key: bytes, 
                    algorithm: str = None, chunk_size: int = 64 * 1024) -> bool:
        """Encrypt file in chunks to handle large files"""
        if algorithm is None:
            algorithm = self.default_algorithm
        
        try:
            with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
                # Write algorithm identifier
                f_out.write(algorithm.encode('ascii') + b'\n')
                
                # For large files, encrypt in chunks
                while True:
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break
                    
                    encrypted_chunk = self.encrypt_data(chunk, key, algorithm)
                    f_out.write(base64.b64decode(encrypted_chunk))
            
            logger.info(f"File encrypted: {input_path} -> {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"File encryption failed: {e}")
            return False
    
    def decrypt_file(self, input_path: str, output_path: str, key: bytes,
                    chunk_size: int = 64 * 1024) -> bool:
        """Decrypt file in chunks"""
        try:
            with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
                # Read algorithm identifier
                algorithm = f_in.readline().strip().decode('ascii')
                
                # Decrypt in chunks
                while True:
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break
                    
                    encrypted_b64 = base64.b64encode(chunk).decode('ascii')
                    decrypted_chunk = self.decrypt_data(encrypted_b64, key, algorithm)
                    f_out.write(decrypted_chunk.encode('utf-8'))
            
            logger.info(f"File decrypted: {input_path} -> {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"File decryption failed: {e}")
            return False
    
    def generate_secure_password(self, length: int = 20, 
                               include_symbols: bool = True,
                               exclude_ambiguous: bool = True) -> str:
        """Generate cryptographically secure password"""
        characters = string.ascii_letters + string.digits
        
        if include_symbols:
            characters += string.punctuation
        
        if exclude_ambiguous:
            # Remove ambiguous characters
            ambiguous = 'il1Lo0O{}[]()/\\\'"`~,;:.<>'
            characters = ''.join(c for c in characters if c not in ambiguous)
        
        # Ensure at least one of each required character type
        password = []
        password.append(secrets.choice(string.ascii_lowercase))
        password.append(secrets.choice(string.ascii_uppercase))
        password.append(secrets.choice(string.digits))
        
        if include_symbols:
            password.append(secrets.choice(string.punctuation))
        
        # Fill remaining length
        remaining_length = length - len(password)
        password.extend(secrets.choice(characters) for _ in range(remaining_length))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        charset_size = 0
        
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * (charset_size ** 0.5)
        return round(entropy, 2)
    
    def verify_password_strength(self, password: str) -> dict:
        """Comprehensive password strength verification"""
        analysis = {
            'length': len(password),
            'has_upper': any(c.isupper() for c in password),
            'has_lower': any(c.islower() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_symbol': any(c in string.punctuation for c in password),
            'entropy': self.calculate_entropy(password),
            'common_patterns': [],
            'score': 0,
            'strength': 'Very Weak'
        }
        
        # Check for common patterns
        common_patterns = [
            '123', 'abc', 'qwerty', 'asdf', 'password', 'admin',
            'letmein', 'welcome', 'monkey', 'dragon', 'baseball'
        ]
        
        for pattern in common_patterns:
            if pattern in password.lower():
                analysis['common_patterns'].append(pattern)
        
        # Calculate score
        score = 0
        
        # Length score
        if analysis['length'] >= 8:
            score += 1
        if analysis['length'] >= 12:
            score += 1
        if analysis['length'] >= 16:
            score += 1
        
        # Character diversity
        if analysis['has_upper']:
            score += 1
        if analysis['has_lower']:
            score += 1
        if analysis['has_digit']:
            score += 1
        if analysis['has_symbol']:
            score += 1
        
        # Entropy score
        if analysis['entropy'] > 50:
            score += 1
        if analysis['entropy'] > 75:
            score += 1
        
        # Penalize common patterns
        if analysis['common_patterns']:
            score = max(0, score - len(analysis['common_patterns']))
        
        analysis['score'] = min(10, score)
        
        # Determine strength
        if analysis['score'] <= 2:
            analysis['strength'] = 'Very Weak'
        elif analysis['score'] <= 4:
            analysis['strength'] = 'Weak'
        elif analysis['score'] <= 6:
            analysis['strength'] = 'Fair'
        elif analysis['score'] <= 8:
            analysis['strength'] = 'Strong'
        else:
            analysis['strength'] = 'Excellent'
        
        return analysis