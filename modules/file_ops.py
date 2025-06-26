import hashlib
import os
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger(__name__)

def check_file_hash(file_path):
    """
    Calculate the SHA-256 hash of a file.
    
    Args:
        file_path (str): Path to the file.
    
    Returns:
        dict: Dictionary containing file hash or error message.
    """
    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {"error": "File not found"}
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        hash_value = sha256_hash.hexdigest()
        logger.info(f"File hash calculated for {file_path}: {hash_value}")
        return {"hash": hash_value}
    except Exception as e:
        logger.error(f"File hash error: {str(e)}")
        return {"error": f"Failed to calculate hash: {str(e)}"}

def encrypt_decrypt_file(file_path, operation):
    """
    Encrypt or decrypt a file using Fernet symmetric encryption.
    
    Args:
        file_path (str): Path to the file.
        operation (str): 'encrypt' or 'decrypt'.
    
    Returns:
        dict: Dictionary containing operation status and output path or error message.
    """
    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {"error": "File not found"}
        key = Fernet.generate_key()
        fernet = Fernet(key)
        with open(file_path, "rb") as f:
            data = f.read()
        if operation == "encrypt":
            result = fernet.encrypt(data)
            output_path = file_path + ".encrypted"
        else:
            result = fernet.decrypt(data)
            output_path = file_path + ".decrypted"
        with open(output_path, "wb") as f:
            f.write(result)
        logger.info(f"File {operation}ed: {output_path}")
        return {"status": f"File {operation}ed successfully", "output": output_path, "key": key.decode()}
    except Exception as e:
        logger.error(f"File {operation} error: {str(e)}")
        return {"error": f"Failed to {operation} file: {str(e)}"}
