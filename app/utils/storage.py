import os
import uuid
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

def save_uploaded_file(file: FileStorage, upload_folder: str, storage_filename: str) -> tuple[int, str]:
    """
    Save an uploaded file to the private storage folder.
    Returns (file_size_bytes, absolute_path).
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
    return file_size, str(target_path)

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
