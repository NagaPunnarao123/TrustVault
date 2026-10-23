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
