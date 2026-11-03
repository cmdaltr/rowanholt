"""
Unified encryption utilities for Dernvale DF Acceleration Suite

Provides consistent encryption/decryption across acquisition modules.
Eliminates duplicate encryption code found in 3+ files.

Replaces:
- acquisition/python/gandalf.py: generate_filekey(), generate_cipher()
- acquisition/python/collect_artefacts-py: encrypt_archive()
- acquisition/bash/gandalf.sh: encrypt_archive() (OpenSSL-based)
"""

import os
import base64
from pathlib import Path
from typing import Tuple, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Standard parameters
DEFAULT_SALT = b"isengard.pork"  # Default salt for password-based encryption
DEFAULT_ITERATIONS = 480000  # PBKDF2 iterations (OWASP recommended 2023)


class CryptoManager:
    """
    Unified cryptography manager for forensic evidence encryption.

    Supports both key-based and password-based encryption using Fernet
    (symmetric encryption with AES-128-CBC and HMAC-SHA256).
    """

    def __init__(self):
        self.key: Optional[bytes] = None
        self.cipher: Optional[Fernet] = None

    def generate_key(self) -> bytes:
        """
        Generate a new Fernet encryption key.

        Returns:
            32-byte URL-safe base64-encoded key

        Example:
            >>> crypto = CryptoManager()
            >>> key = crypto.generate_key()
            >>> len(key)
            44
        """
        self.key = Fernet.generate_key()
        return self.key

    def load_key(self, key_path: str) -> bytes:
        """
        Load encryption key from file.

        Args:
            key_path: Path to key file

        Returns:
            Encryption key

        Raises:
            FileNotFoundError: If key file doesn't exist
        """
        with open(key_path, "rb") as f:
            self.key = f.read()
        return self.key

    def save_key(self, key_path: str, key: Optional[bytes] = None):
        """
        Save encryption key to file.

        Args:
            key_path: Path to save key
            key: Key to save (uses instance key if not provided)

        Example:
            >>> crypto = CryptoManager()
            >>> crypto.generate_key()
            >>> crypto.save_key("/tmp/shadowfax.key")
        """
        key = key or self.key
        if not key:
            raise ValueError("No key to save. Generate or load a key first.")

        Path(key_path).parent.mkdir(parents=True, exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(key)

    def derive_key_from_password(
        self, password: str, salt: bytes = DEFAULT_SALT, iterations: int = DEFAULT_ITERATIONS
    ) -> bytes:
        """
        Derive encryption key from password using PBKDF2.

        Args:
            password: User password
            salt: Salt for key derivation (default: b"isengard.pork")
            iterations: PBKDF2 iterations (default: 480000)

        Returns:
            Derived encryption key

        Example:
            >>> crypto = CryptoManager()
            >>> key = crypto.derive_key_from_password("MyPassword123")
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return self.key

    def set_key(self, key: bytes):
        """
        Set encryption key directly.

        Args:
            key: Fernet encryption key
        """
        self.key = key

    def get_cipher(self, key: Optional[bytes] = None) -> Fernet:
        """
        Get Fernet cipher instance.

        Args:
            key: Encryption key (uses instance key if not provided)

        Returns:
            Fernet cipher instance

        Raises:
            ValueError: If no key is available
        """
        key = key or self.key
        if not key:
            raise ValueError("No key available. Generate, load, or derive a key first.")

        self.cipher = Fernet(key)
        return self.cipher

    def encrypt_file(
        self, input_path: str, output_path: Optional[str] = None, key: Optional[bytes] = None
    ) -> str:
        """
        Encrypt a file.

        Args:
            input_path: Path to file to encrypt
            output_path: Path for encrypted output (default: input_path + '.enc')
            key: Encryption key (uses instance key if not provided)

        Returns:
            Path to encrypted file

        Example:
            >>> crypto = CryptoManager()
            >>> crypto.generate_key()
            >>> encrypted = crypto.encrypt_file("/tmp/evidence.tar.gz")
            >>> encrypted
            '/tmp/evidence.tar.gz.enc'
        """
        if output_path is None:
            output_path = input_path + ".enc"

        cipher = self.get_cipher(key)

        with open(input_path, "rb") as f:
            plaintext = f.read()

        ciphertext = cipher.encrypt(plaintext)

        with open(output_path, "wb") as f:
            f.write(ciphertext)

        return output_path

    def decrypt_file(
        self, input_path: str, output_path: Optional[str] = None, key: Optional[bytes] = None
    ) -> str:
        """
        Decrypt a file.

        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted output (default: removes '.enc')
            key: Decryption key (uses instance key if not provided)

        Returns:
            Path to decrypted file

        Raises:
            cryptography.fernet.InvalidToken: If key is incorrect

        Example:
            >>> crypto = CryptoManager()
            >>> crypto.load_key("/tmp/shadowfax.key")
            >>> decrypted = crypto.decrypt_file("/tmp/evidence.tar.gz.enc")
        """
        if output_path is None:
            if input_path.endswith(".enc"):
                output_path = input_path[:-4]
            else:
                output_path = input_path + ".dec"

        cipher = self.get_cipher(key)

        with open(input_path, "rb") as f:
            ciphertext = f.read()

        plaintext = cipher.decrypt(ciphertext)

        with open(output_path, "wb") as f:
            f.write(plaintext)

        return output_path

    def encrypt_data(self, data: bytes, key: Optional[bytes] = None) -> bytes:
        """
        Encrypt bytes in memory.

        Args:
            data: Data to encrypt
            key: Encryption key

        Returns:
            Encrypted data
        """
        cipher = self.get_cipher(key)
        return cipher.encrypt(data)

    def decrypt_data(self, data: bytes, key: Optional[bytes] = None) -> bytes:
        """
        Decrypt bytes in memory.

        Args:
            data: Data to decrypt
            key: Decryption key

        Returns:
            Decrypted data
        """
        cipher = self.get_cipher(key)
        return cipher.decrypt(data)


# Convenience functions for common use cases


def encrypt_archive_with_key(
    archive_path: str, key_output_path: Optional[str] = None
) -> Tuple[str, str]:
    """
    Encrypt archive with newly generated key.

    Args:
        archive_path: Path to archive to encrypt
        key_output_path: Path to save key (default: shadowfax.key in same dir)

    Returns:
        Tuple of (encrypted_file_path, key_file_path)

    Example:
        >>> encrypted, key = encrypt_archive_with_key("/tmp/evidence.tar.gz")
        >>> encrypted
        '/tmp/evidence.tar.gz.enc'
        >>> key
        '/tmp/shadowfax.key'
    """
    crypto = CryptoManager()
    crypto.generate_key()

    # Encrypt file
    encrypted_path = crypto.encrypt_file(archive_path)

    # Save key
    if key_output_path is None:
        key_output_path = str(Path(archive_path).parent / "shadowfax.key")
    crypto.save_key(key_output_path)

    return encrypted_path, key_output_path


def encrypt_archive_with_password(
    archive_path: str, password: str, salt: bytes = DEFAULT_SALT
) -> str:
    """
    Encrypt archive with password.

    Args:
        archive_path: Path to archive to encrypt
        password: Encryption password
        salt: Salt for key derivation

    Returns:
        Path to encrypted file

    Example:
        >>> encrypted = encrypt_archive_with_password(
        ...     "/tmp/evidence.tar.gz",
        ...     "MySecurePassword123"
        ... )
    """
    crypto = CryptoManager()
    crypto.derive_key_from_password(password, salt)
    return crypto.encrypt_file(archive_path)


def decrypt_archive_with_key(encrypted_path: str, key_path: str) -> str:
    """
    Decrypt archive using key file.

    Args:
        encrypted_path: Path to encrypted archive
        key_path: Path to key file

    Returns:
        Path to decrypted file

    Example:
        >>> decrypted = decrypt_archive_with_key(
        ...     "/tmp/evidence.tar.gz.enc",
        ...     "/tmp/shadowfax.key"
        ... )
    """
    crypto = CryptoManager()
    crypto.load_key(key_path)
    return crypto.decrypt_file(encrypted_path)


def decrypt_archive_with_password(
    encrypted_path: str, password: str, salt: bytes = DEFAULT_SALT
) -> str:
    """
    Decrypt archive using password.

    Args:
        encrypted_path: Path to encrypted archive
        password: Decryption password
        salt: Salt used for key derivation

    Returns:
        Path to decrypted file

    Example:
        >>> decrypted = decrypt_archive_with_password(
        ...     "/tmp/evidence.tar.gz.enc",
        ...     "MySecurePassword123"
        ... )
    """
    crypto = CryptoManager()
    crypto.derive_key_from_password(password, salt)
    return crypto.decrypt_file(encrypted_path)


def generate_key_file(output_path: str = "shadowfax.key") -> str:
    """
    Generate and save a new encryption key.

    Args:
        output_path: Path to save key file

    Returns:
        Path to key file

    Example:
        >>> key_path = generate_key_file("/tmp/my_key.key")
    """
    crypto = CryptoManager()
    crypto.generate_key()
    crypto.save_key(output_path)
    return output_path


def verify_key(key_path: str) -> bool:
    """
    Verify a key file is valid.

    Args:
        key_path: Path to key file

    Returns:
        True if key is valid, False otherwise
    """
    try:
        with open(key_path, "rb") as f:
            key = f.read()
        Fernet(key)
        return True
    except Exception:
        return False
