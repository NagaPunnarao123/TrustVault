import io
import os
from pathlib import Path
from app.models import Document
from app.extensions import db
from app.utils.storage import delete_stored_file

def test_disallowed_file_types_rejected(client, auth, seed_tenants):
    """Executable or script files must be strictly rejected during upload."""
    auth.login(email='owner_a@alpha.com', password='Password123!')

    disallowed_files = [
        ('malware.exe', b'MZ executable binary payload'),
        ('script.sh', b'#!/bin/bash\nrm -rf /'),
        ('backdoor.py', b'import socket; print("exploit")'),
        ('shell.php', b'<?php phpinfo(); ?>'),
    ]

    for filename, content in disallowed_files:
        resp = client.post('/documents/upload', data={
            'file': (io.BytesIO(content), filename),
            'category': 'General',
            'description': 'Disallowed'
        }, follow_redirects=True)

        assert b'Disallowed file type' in resp.data


def test_allowed_file_types_accepted(client, auth, seed_tenants, app):
    """Supported safe document and image formats are accepted."""
    auth.login(email='owner_a@alpha.com', password='Password123!')

    allowed_files = [
        ('report.pdf', b'%PDF-1.4 sample PDF content'),
        ('notes.txt', b'Simple plain text meeting notes'),
        ('data.csv', b'id,name,role\n1,Alice,Owner'),
        ('image.png', b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR...'),
    ]

    for filename, content in allowed_files:
        resp = client.post('/documents/upload', data={
            'file': (io.BytesIO(content), filename),
            'category': 'General',
            'description': 'Valid upload'
        }, follow_redirects=True)

        assert resp.status_code == 200
        # HTML template autoescapes quotes to &#39; to protect against XSS
        assert "uploaded successfully" in resp.data.decode('utf-8')
        assert filename in resp.data.decode('utf-8')


def test_random_uuid_storage_name_and_private_location(client, auth, seed_tenants, app):
    """
    Uploaded files must be stored with a random UUID filename in private storage,
    never under the user's raw filename, and NEVER in the public static/ directory.
    """
    auth.login(email='owner_a@alpha.com', password='Password123!')

    client.post('/documents/upload', data={
        'file': (io.BytesIO(b"Confidential payload"), "my_super_secret_file.pdf"),
        'category': 'Confidential',
        'description': 'UUID test'
    }, follow_redirects=True)

    with app.app_context():
        doc = Document.query.filter_by(original_filename='my_super_secret_file.pdf').first()
        assert doc is not None

        # Verify storage filename is a UUID string with extension
        storage_name = doc.storage_filename
        assert storage_name != 'my_super_secret_file.pdf'
        assert storage_name.endswith('.pdf')
        assert len(storage_name) >= 32

        # Verify physical file exists in app.config['UPLOAD_FOLDER']
        storage_path = Path(app.config['UPLOAD_FOLDER']) / storage_name
        assert storage_path.exists() is True
        assert storage_path.read_bytes() == b"Confidential payload"

        # Verify file does NOT exist in static folder
        static_path = Path(app.root_path) / 'static' / 'my_super_secret_file.pdf'
        assert static_path.exists() is False


def test_path_traversal_prevention_in_filename(client, auth, seed_tenants, app):
    """
    Path traversal sequences like `../../etc/passwd` in filenames must be sanitized
    and must not escape the upload root directory.
    """
    auth.login(email='owner_a@alpha.com', password='Password123!')

    traversal_filename = "../../../etc/passwd.pdf"
    client.post('/documents/upload', data={
        'file': (io.BytesIO(b"safe test content"), traversal_filename),
        'category': 'General',
        'description': 'Traversal test'
    }, follow_redirects=True)

    with app.app_context():
        doc = Document.query.filter_by(original_filename='etc_passwd.pdf').first()
        if not doc:
            doc = Document.query.filter(Document.original_filename.like('%passwd%')).first()

        assert doc is not None
        # Must not contain directory traversal characters
        assert '../' not in doc.original_filename
        assert '..\\' not in doc.original_filename

        # Physical file is safely inside UPLOAD_FOLDER
        physical_path = Path(app.config['UPLOAD_FOLDER']) / doc.storage_filename
        assert physical_path.exists() is True
        assert str(physical_path.resolve()).startswith(str(Path(app.config['UPLOAD_FOLDER']).resolve()))


def test_document_deletion_removes_physical_file(client, auth, seed_tenants, app):
    """Deleting a document removes the physical file from disk and marks DB record as deleted."""
    auth.login(email='owner_a@alpha.com', password='Password123!')

    client.post('/documents/upload', data={
        'file': (io.BytesIO(b"To be deleted"), "delete_me.pdf"),
        'category': 'General',
        'description': 'Delete test'
    }, follow_redirects=True)

    with app.app_context():
        doc = Document.query.filter_by(original_filename='delete_me.pdf').first()
        doc_id = doc.id
        storage_name = doc.storage_filename
        file_path = Path(app.config['UPLOAD_FOLDER']) / storage_name
        assert file_path.exists() is True

    # Delete the document
    del_resp = client.post(f'/documents/{doc_id}/delete', follow_redirects=True)
    assert b'has been deleted' in del_resp.data

    # Verify physical file is gone
    assert file_path.exists() is False

    # Verify document is marked as deleted in DB
    with app.app_context():
        doc_after = db.session.get(Document, doc_id)
        assert doc_after.is_deleted is True
