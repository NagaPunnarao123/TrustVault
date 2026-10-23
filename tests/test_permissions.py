import io
import pytest
from app.models import Document, AccessPermission
from app.extensions import db

def test_viewer_cannot_upload_document(client, auth, seed_tenants):
    """VIEWER role must be strictly blocked from the upload route (403 Forbidden)."""
    auth.login(email='viewer_a@alpha.com', password='Password123!')

    # GET upload page
    get_resp = client.get('/documents/upload')
    assert get_resp.status_code == 403

    # POST upload attempt
    post_resp = client.post('/documents/upload', data={
        'file': (io.BytesIO(b"Viewer payload"), "viewer_doc.pdf"),
        'category': 'General',
        'description': 'Attempt'
    })
    assert post_resp.status_code == 403


def test_viewer_cannot_access_unshared_document(client, auth, seed_tenants, app):
    """A VIEWER within the same tenant cannot download a document unless explicitly shared."""
    # Owner A uploads a document
    auth.login(email='owner_a@alpha.com', password='Password123!')
    client.post('/documents/upload', data={
        'file': (io.BytesIO(b"Owner Private File"), "owner_private.pdf"),
        'category': 'Confidential',
        'description': 'Private'
    }, follow_redirects=True)

    with app.app_context():
        doc = Document.query.filter_by(original_filename='owner_private.pdf').first()
        doc_id = doc.id

    auth.logout()

    # Viewer A attempts to download without permission
    auth.login(email='viewer_a@alpha.com', password='Password123!')
    download_resp = client.get(f'/documents/{doc_id}/download')

    assert download_resp.status_code == 403


def test_share_and_immediate_revocation_lifecycle(client, auth, seed_tenants, app):
    """
    Test the full sharing and revocation lifecycle:
    1. Owner uploads file.
    2. Viewer cannot download (403).
    3. Owner grants permission to Viewer.
    4. Viewer can now download (200).
    5. Owner revokes permission.
    6. Viewer download is immediately blocked (403).
    """
    # 1. Owner uploads
    auth.login(email='owner_a@alpha.com', password='Password123!')
    client.post('/documents/upload', data={
        'file': (io.BytesIO(b"Lifecycle test content"), "lifecycle.pdf"),
        'category': 'General',
        'description': 'Lifecycle'
    }, follow_redirects=True)

    with app.app_context():
        doc = Document.query.filter_by(original_filename='lifecycle.pdf').first()
        doc_id = doc.id

    # 2. Grant permission to Viewer A
    share_resp = client.post(f'/documents/{doc_id}/manage-access', data={
        'recipient_email': 'viewer_a@alpha.com'
    }, follow_redirects=True)
    assert b'Access granted to' in share_resp.data

    auth.logout()

    # 3. Viewer logs in and downloads successfully
    auth.login(email='viewer_a@alpha.com', password='Password123!')
    viewer_dl = client.get(f'/documents/{doc_id}/download')
    assert viewer_dl.status_code == 200
    assert viewer_dl.data == b"Lifecycle test content"

    auth.logout()

    # 4. Owner logs in and revokes permission
    auth.login(email='owner_a@alpha.com', password='Password123!')
    viewer_id = seed_tenants['viewer_a_id']
    revoke_resp = client.post(f'/documents/{doc_id}/revoke-access/{viewer_id}', follow_redirects=True)
    assert b'Access revoked' in revoke_resp.data

    auth.logout()

    # 5. Viewer attempts to download again -> IMMEDIATELY BLOCKED (403)
    auth.login(email='viewer_a@alpha.com', password='Password123!')
    blocked_dl = client.get(f'/documents/{doc_id}/download')
    assert blocked_dl.status_code == 403


def test_viewer_cannot_delete_or_manage_sharing(client, auth, seed_tenants, app):
    """VIEWER role cannot delete documents or administer sharing permissions."""
    auth.login(email='owner_a@alpha.com', password='Password123!')
    client.post('/documents/upload', data={
        'file': (io.BytesIO(b"Owner file"), "target.pdf"),
        'category': 'General',
        'description': 'Target'
    }, follow_redirects=True)

    with app.app_context():
        doc = Document.query.filter_by(original_filename='target.pdf').first()
        doc_id = doc.id

    auth.logout()

    auth.login(email='viewer_a@alpha.com', password='Password123!')

    # Attempt to manage access
    manage_resp = client.get(f'/documents/{doc_id}/manage-access')
    assert manage_resp.status_code == 403

    # Attempt to delete
    del_resp = client.post(f'/documents/{doc_id}/delete')
    assert del_resp.status_code == 403
