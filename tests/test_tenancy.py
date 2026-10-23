import io
import pytest
from app.models import Document, AccessPermission
from app.extensions import db

def test_cross_tenant_download_prohibited(client, auth, seed_tenants, app):
    """
    CRITICAL MULTI-TENANCY TEST:
    A user from Tenant B must never be able to download a document belonging to Tenant A,
    even if they know the document's ID.
    """
    # 1. Login as Owner A (Tenant A) and upload a document
    auth.login(email='owner_a@alpha.com', password='Password123!')
    upload_resp = client.post('/documents/upload', data={
        'file': (io.BytesIO(b"Alpha Confidential Data"), "alpha_secrets.pdf"),
        'category': 'Confidential',
        'description': 'Proprietary Alpha Document'
    }, follow_redirects=True)
    assert upload_resp.status_code == 200

    with app.app_context():
        doc_a = Document.query.filter_by(original_filename='alpha_secrets.pdf').first()
        assert doc_a is not None
        doc_id = doc_a.id

    auth.logout()

    # 2. Login as Owner B (Tenant B) and attempt to download Tenant A's document
    auth.login(email='owner_b@beta.com', password='Password123!')
    cross_resp = client.get(f'/documents/{doc_id}/download')

    # Must be strictly rejected with HTTP 403 Forbidden
    assert cross_resp.status_code == 403


def test_cross_tenant_delete_prohibited(client, auth, seed_tenants, app):
    """A user in Tenant B cannot delete a document belonging to Tenant A."""
    auth.login(email='owner_a@alpha.com', password='Password123!')
    client.post('/documents/upload', data={
        'file': (io.BytesIO(b"Alpha File"), "alpha_doc.pdf"),
        'category': 'General',
        'description': 'Alpha'
    }, follow_redirects=True)

    with app.app_context():
        doc = Document.query.filter_by(original_filename='alpha_doc.pdf').first()
        doc_id = doc.id

    auth.logout()

    # Owner B attempts to delete
    auth.login(email='owner_b@beta.com', password='Password123!')
    del_resp = client.post(f'/documents/{doc_id}/delete')
    assert del_resp.status_code == 403

    # Document must still exist
    with app.app_context():
        doc_check = db.session.get(Document, doc_id)
        assert doc_check.is_deleted is False


def test_cross_tenant_sharing_prevented(client, auth, seed_tenants, app):
    """
    Owners cannot share documents with users belonging to a different organization.
    Tenant boundary must be enforced server-side.
    """
    auth.login(email='owner_a@alpha.com', password='Password123!')
    client.post('/documents/upload', data={
        'file': (io.BytesIO(b"Important"), "share_test.pdf"),
        'category': 'Legal',
        'description': 'Legal memo'
    }, follow_redirects=True)

    with app.app_context():
        doc = Document.query.filter_by(original_filename='share_test.pdf').first()
        doc_id = doc.id

    # Attempt to share with viewer_b@beta.com (Tenant B member)
    share_resp = client.post(f'/documents/{doc_id}/manage-access', data={
        'recipient_email': 'viewer_b@beta.com'
    }, follow_redirects=True)

    assert b'Cross-organization sharing is prohibited' in share_resp.data

    # Verify no permission was inserted
    with app.app_context():
        perm = AccessPermission.query.filter_by(document_id=doc_id).first()
        assert perm is None


def test_document_listing_strictly_scoped_to_active_tenant(client, auth, seed_tenants, app):
    """Ensure documents from other tenants never appear in my-documents or shared-with-me."""
    # Upload doc in Tenant A
    auth.login(email='owner_a@alpha.com', password='Password123!')
    client.post('/documents/upload', data={
        'file': (io.BytesIO(b"Alpha File"), "unique_alpha_statement.pdf"),
        'category': 'Financial',
        'description': 'Statement'
    }, follow_redirects=True)
    auth.logout()

    # Upload doc in Tenant B
    auth.login(email='owner_b@beta.com', password='Password123!')
    client.post('/documents/upload', data={
        'file': (io.BytesIO(b"Beta File"), "unique_beta_invoice.pdf"),
        'category': 'Financial',
        'description': 'Invoice'
    }, follow_redirects=True)

    # Check Tenant B's listing
    my_docs = client.get('/documents/my-documents')
    assert b'unique_beta_invoice.pdf' in my_docs.data
    assert b'unique_alpha_statement.pdf' not in my_docs.data
