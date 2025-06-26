import os
import hashlib
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger(__name__)

def check_file_hash(file_path):
    try:
        if not os.path.exists(file_path):
            return {"error": "File not found"}
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
        return {"status": "Success", "file": file_path, "hash": file_hash}
    except Exception as e:
        logger.error(f"File hash error: {str(e)}")
        return {"error": f"File hash check failed: {str(e)}"}

def encrypt_decrypt_file(file_path, operation, key_file="secret.key"):
    try:
        if not os.path.exists(file_path):
            return {"error": "File not found"}
        if operation == "encrypt" and not os.path.exists(key_file):
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
        elif not os.path.exists(key_file):
            return {"error": "Key file not found for decryption"}
        with open(key_file, 'rb') as f:
            key = f.read()
        fernet = Fernet(key)
        with open(file_path, 'rb') as f:
            data = f.read()
        if operation == "encrypt":
            encrypted = fernet.encrypt(data)
            output_path = file_path + ".enc"
            with open(output_path, 'wb') as f:
                f.write(encrypted)
            return {"status": "File encrypted", "output": output_path}
        elif operation == "decrypt":
            decrypted = fernet.decrypt(data)
            output_path = file_path.replace(".enc", ".dec")
            with open(output_path, 'wb') as f:
                f.write(decrypted)
            return {"status": "File decrypted", "output": output_path}
        else:
            return {"error": "Invalid operation"}
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        return {"error": f"Encryption/decryption failed: {str(e)}"}