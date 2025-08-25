"""Simulation of a server's padding oracle for AES-CBC cipher."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

import pkcs7
from settings import KEY, IV

_CIPHER = Cipher(algorithms.AES256(KEY), modes.CBC(IV))

def encrypt(plaintext: bytes, native_padder: bool = False) -> bytes:
    """Encrypts the plaintext using AES-256-CBC returning the ciphertext."""
    e = _CIPHER.encryptor()
    padder = padding.PKCS7(len(KEY) * 8).padder()

    if native_padder:
        padded_data = padder.update(plaintext) + padder.finalize()
    else:
        padded_data = pkcs7.pad(plaintext)

    return e.update(padded_data) + e.finalize()

def decrypt(ciphertext: bytes) -> bytes:
    """Decrypts the ciphertext using AES-256-CBC returning the plaintext."""
    d = _CIPHER.decryptor()
    return d.update(ciphertext) + d.finalize()

def oracle(ciphertext: bytes, native_padder: bool = False) -> bool:
    """Returns whether the plaintext padding was correct or not."""
    unpadder = padding.PKCS7(len(KEY) * 8).unpadder()
    plaintext = decrypt(ciphertext)

    if native_padder:
        try:
            _ = unpadder.update(plaintext) + unpadder.finalize()
            return True
        except ValueError:
            return False
    else:
        return pkcs7.is_pkcs7_padded(plaintext)
