from cryptography.fernet import Fernet
import os

def get_cipher():
    key = os.environ.get('ENCRYPTION_KEY', None) 
    if not key:
        key = Fernet.generate_key() 
    cipher = Fernet(key)
    return cipher
