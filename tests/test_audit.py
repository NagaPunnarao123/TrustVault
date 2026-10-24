import io
import pytest
from app.models import AuditEvent, Document
from app.extensions import db

def test_audit_logs_login_events(client, auth, seed_tenants, app):
    """Verify login successes and failures generate verifiable audit event records."""
    # Failed login
    auth.login(email='owner_a@alpha.com', password='WrongPassword!')
    
    # Successful login
    auth.login(email='owner_a@alpha.com', password='Password123!')

    with app.app_context():
        fail_event = AuditEvent.query.filter_by(action='LOGIN_FAILURE').first()
        assert fail_event is not None
        assert fail_event.status == 'FAILURE'

        success_event = AuditEvent.query.filter_by(action='LOGIN_SUCCESS').first()
        assert success_event is not None
        assert success_event.status == 'SUCCESS'
        assert success_event.user_id == seed_tenants['owner_a_id']


def test_audit_logs_document_operations(client, auth, seed_tenants, app):
    """
    Verify upload, download, share, revoke, and delete actions
    all produce distinct, queryable audit trail entries.
    """
    auth.login(email='owner_a@alpha.com', password='Password123!')

    # 1. Upload
    client.post('/documents/upload', data={
        'file': (io.BytesIO(b"Audited document content"), "audited.pdf"),
        'category': 'Technical',
        'description': 'Audit test'
    }, follow_redirects=True)

    with app.app_context():
        doc = Document.query.filter_by(original_filename='audited.pdf').first()
        doc_id = doc.id
        upload_event = AuditEvent.query.filter_by(
            action='UPLOAD_DOCUMENT', resource_id=str(doc_id)
        ).first()
        assert upload_event is not None
        assert upload_event.status == 'SUCCESS'

    # 2. Share
    client.post(f'/documents/{doc_id}/manage-access', data={
        'recipient_email': 'viewer_a@alpha.com'
    }, follow_redirects=True)

    with app.app_context():
        share_event = AuditEvent.query.filter_by(
            action='GRANT_PERMISSION', resource_id=str(doc_id)
        ).first()
        assert share_event is not None
        assert share_event.status == 'SUCCESS'

    # 3. Download
    client.get(f'/documents/{doc_id}/download')

    with app.app_context():
        dl_event = AuditEvent.query.filter_by(
            action='DOWNLOAD_DOCUMENT', resource_id=str(doc_id)
        ).first()
        assert dl_event is not None
        assert dl_event.status == 'SUCCESS'

    # 4. Revoke
    viewer_id = seed_tenants['viewer_a_id']
    client.post(f'/documents/{doc_id}/revoke-access/{viewer_id}', follow_redirects=True)

    with app.app_context():
        revoke_event = AuditEvent.query.filter_by(
            action='REVOKE_PERMISSION', resource_id=str(doc_id)
        ).first()
        assert revoke_event is not None
        assert revoke_event.status == 'SUCCESS'

    # 5. Delete
    client.post(f'/documents/{doc_id}/delete', follow_redirects=True)

    with app.app_context():
        del_event = AuditEvent.query.filter_by(
            action='DELETE_DOCUMENT', resource_id=str(doc_id)
        ).first()
        assert del_event is not None
        assert del_event.status == 'SUCCESS'


def test_audit_logs_access_denied_events(client, auth, seed_tenants, app):
    """Rejected access attempts (e.g. cross-tenant or unshared document access) generate DENIED audit records."""
    # Owner A uploads
    auth.login(email='owner_a@alpha.com', password='Password123!')
    client.post('/documents/upload', data={
        'file': (io.BytesIO(b"Alpha Classified"), "alpha_classified.pdf"),
        'category': 'Confidential',
        'description': 'Top secret'
    }, follow_redirects=True)

    with app.app_context():
        doc = Document.query.filter_by(original_filename='alpha_classified.pdf').first()
        doc_id = doc.id

    auth.logout()

    # Viewer B from Tenant B attempts to download
    auth.login(email='viewer_b@beta.com', password='Password123!')
    client.get(f'/documents/{doc_id}/download')

    with app.app_context():
        denied_event = AuditEvent.query.filter_by(
            action='ACCESS_DENIED', status='DENIED', resource_id=str(doc_id)
        ).first()
        assert denied_event is not None
        assert denied_event.user_id == seed_tenants['viewer_b_id']


def test_magic_bytes_rejects_disguised_executables(client, auth, seed_tenants):
    """
    Magic byte inspection must reject disguised binary executables, web shells,
    and null-byte poisoned files even if they spoof legitimate extensions.
    """
    auth.login(email='owner_a@alpha.com', password='Password123!')

    pe_bytes = bytes([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00])
    elf_bytes = bytes([0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01])
    php_bytes = b'<' + b'?php ' + b'echo 1;'
    sh_bytes = b'#!' + b'/bin/sh\nexit 0'
    null_bytes = b'Report content' + bytes([0x00]) + b'injected payload'
    bad_png = b'Not a real PNG header at all'

    disguised_attacks = [
        ('stealth_payload.png', pe_bytes, 'Executable binary signature detected'),
        ('exploit.pdf', elf_bytes, 'Executable binary signature detected'),
        ('backdoor.jpg', php_bytes, 'Server-side executable script tags detected'),
        ('bad_script.docx', sh_bytes, 'Executable binary signature detected'),
        ('poisoned.txt', null_bytes, 'embedded null bytes'),
        ('fake_image.png', bad_png, 'missing standard PNG signature'),
    ]

    for filename, content, expected_msg in disguised_attacks:
        resp = client.post('/documents/upload', data={
            'file': (io.BytesIO(content), filename),
            'category': 'General',
            'description': 'Disguised attack simulation'
        }, follow_redirects=True)

        assert expected_msg in resp.data.decode('utf-8')


def test_sha256_checksum_and_tamper_detection(client, auth, seed_tenants, app):
    """
    Document delivery must verify cryptographic SHA-256 integrity and detect tampering.
    """
    from pathlib import Path
    auth.login(email='owner_a@alpha.com', password='Password123!')

    # Upload authentic PDF
    upload_resp = client.post('/documents/upload', data={
        'file': (io.BytesIO(b'%PDF-1.7 Authentic signed contract bytes'), 'contract.pdf'),
        'category': 'Legal',
        'description': 'Cryptographic integrity test'
    }, follow_redirects=True)
    assert 'uploaded successfully' in upload_resp.data.decode('utf-8')

    with app.app_context():
        doc = Document.query.filter_by(original_filename='contract.pdf').first()
        assert doc is not None
        assert doc.sha256_checksum is not None
        assert len(doc.sha256_checksum) == 64
        doc_id = doc.id
        storage_filename = doc.storage_filename

    # Normal download succeeds
    dl_resp = client.get(f'/documents/{doc_id}/download')
    assert dl_resp.status_code == 200
    assert dl_resp.data == b'%PDF-1.7 Authentic signed contract bytes'
    dl_resp.close()

    # Simulate physical file tampering on disk
    upload_folder = app.config['UPLOAD_FOLDER']
    physical_file = Path(upload_folder) / storage_filename
    physical_file.write_bytes(b'%PDF-1.7 TAMPERED CORRUPTED CONTENT BY MALICIOUS ACTOR')

    # Tampered download fails integrity verification
    tampered_dl = client.get(f'/documents/{doc_id}/download')
    assert tampered_dl.status_code == 500

    # Verify audit event for tamper detection
    with app.app_context():
        audit = AuditEvent.query.filter_by(action='INTEGRITY_VIOLATION').first()
        assert audit is not None
        assert 'Tampering detected' in audit.details


def test_http_and_download_security_headers(client, auth, seed_tenants, app):
    """
    Verify OWASP security headers on all responses and sandboxing on file downloads.
    """
    # 1. Standard route security headers
    resp = client.get('/auth/login')
    assert resp.status_code == 200
    assert resp.headers.get('X-Frame-Options') == 'DENY'
    assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
    assert 'strict-origin-when-cross-origin' in resp.headers.get('Referrer-Policy', '')
    csp = resp.headers.get('Content-Security-Policy', '')
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp

    # 2. Download route sandboxing headers
    auth.login(email='owner_a@alpha.com', password='Password123!')
    client.post('/documents/upload', data={
        'file': (io.BytesIO(b'%PDF-1.4 header test'), 'headers_doc.pdf'),
        'category': 'General',
        'description': 'Header test'
    }, follow_redirects=True)

    with app.app_context():
        doc = Document.query.filter_by(original_filename='headers_doc.pdf').first()
        doc_id = doc.id

    dl_resp = client.get(f'/documents/{doc_id}/download')
    assert dl_resp.status_code == 200
    assert dl_resp.headers.get('X-Content-Type-Options') == 'nosniff'
    assert dl_resp.headers.get('X-Download-Options') == 'noopen'
    assert 'sandbox' in dl_resp.headers.get('Content-Security-Policy', '')
    dl_resp.close()
