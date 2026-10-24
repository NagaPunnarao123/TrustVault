import os
import uuid
import hashlib
from pathlib import Path
from werkzeug.datastructures import FileStorage

def generate_storage_filename(original_filename: str) -> str:
    """
    Generate a secure random UUID-based storage filename.
    Never uses the user-provided filename on disk to prevent path traversal
    and extension-based execution vulnerabilities.
    """
    ext = ''
    if '.' in original_filename:
        ext = '.' + original_filename.rsplit('.', 1)[1].lower()
    return f"{uuid.uuid4().hex}{ext}"

def calculate_file_sha256(file_path: str) -> str:
    """
    Calculate the SHA-256 cryptographic hash of a stored file.
    Streams the file in 64 KB blocks to handle files of any size efficiently.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(65536):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def save_uploaded_file(file: FileStorage, upload_folder: str, storage_filename: str) -> tuple[int, str, str]:
    """
    Save an uploaded file to the private storage folder.
    Returns (file_size_bytes, absolute_path, sha256_checksum).
    Ensures upload directory exists and guards against path escape.
    """
    folder_path = Path(upload_folder).resolve()
    folder_path.mkdir(parents=True, exist_ok=True)
    
    target_path = (folder_path / storage_filename).resolve()
    
    # Path traversal safety check: target must be inside folder_path
    if not str(target_path).startswith(str(folder_path)):
        raise ValueError("Invalid storage path: directory traversal detected.")
    
    file.save(str(target_path))
    file_size = target_path.stat().st_size
    sha256_checksum = calculate_file_sha256(str(target_path))
    
    return file_size, str(target_path), sha256_checksum

def delete_stored_file(upload_folder: str, storage_filename: str) -> bool:
    """
    Safely delete a physical file from the storage folder.
    """
    try:
        folder_path = Path(upload_folder).resolve()
        target_path = (folder_path / storage_filename).resolve()
        
        # Path traversal guard
        if not str(target_path).startswith(str(folder_path)):
            return False
            
        if target_path.exists() and target_path.is_file():
            target_path.unlink()
            return True
    except Exception:
        pass
    return False
