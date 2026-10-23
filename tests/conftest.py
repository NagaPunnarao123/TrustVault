import os
import tempfile
import pytest
from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models import Tenant, User, TenantMembership

@pytest.fixture
def app():
    """Create and configure a clean Flask application instance for each test."""
    temp_upload_dir = tempfile.TemporaryDirectory()

    class CustomTestingConfig(TestingConfig):
        UPLOAD_FOLDER = temp_upload_dir.name
        WTF_CSRF_ENABLED = False  # Disabled for unit tests to simplify direct POSTs

    app = create_app(CustomTestingConfig)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

    temp_upload_dir.cleanup()


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def cli_runner(app):
    """A test CLI runner for app commands."""
    return app.test_cli_runner()


class AuthActions:
    """Helper methods for simulating authentication in tests."""
    def __init__(self, client):
        self._client = client

    def register(self, email='test@example.com', password='Password123!',
                 full_name='Test User', organization_name='Test Organization'):
        return self._client.post('/auth/register', data={
            'email': email,
            'password': password,
            'confirm_password': password,
            'full_name': full_name,
            'organization_name': organization_name
        }, follow_redirects=True)

    def login(self, email='test@example.com', password='Password123!'):
        return self._client.post('/auth/login', data={
            'email': email,
            'password': password
        }, follow_redirects=True)

    def logout(self):
        return self._client.get('/auth/logout', follow_redirects=True)


@pytest.fixture
def auth(client):
    return AuthActions(client)


@pytest.fixture
def seed_tenants(app):
    """
    Seed two separate tenants with an Owner and a Viewer in each tenant
    to thoroughly test multi-tenancy and RBAC isolation.
    """
    with app.app_context():
        # Tenant 1: Alpha Corp
        tenant_a = Tenant(name='Alpha Corp', slug='alpha-corp')
        db.session.add(tenant_a)
        db.session.flush()

        # Tenant 1 - Owner
        owner_a = User(email='owner_a@alpha.com', full_name='Owner Alpha', is_active_account=True)
        owner_a.set_password('Password123!')
        db.session.add(owner_a)
        db.session.flush()

        membership_oa = TenantMembership(user_id=owner_a.id, tenant_id=tenant_a.id, role=TenantMembership.ROLE_OWNER)
        db.session.add(membership_oa)

        # Tenant 1 - Viewer
        viewer_a = User(email='viewer_a@alpha.com', full_name='Viewer Alpha', is_active_account=True)
        viewer_a.set_password('Password123!')
        db.session.add(viewer_a)
        db.session.flush()

        membership_va = TenantMembership(user_id=viewer_a.id, tenant_id=tenant_a.id, role=TenantMembership.ROLE_VIEWER)
        db.session.add(membership_va)

        # Tenant 1 - Admin
        admin_a = User(email='admin_a@alpha.com', full_name='Admin Alpha', is_active_account=True)
        admin_a.set_password('Password123!')
        db.session.add(admin_a)
        db.session.flush()

        membership_aa = TenantMembership(user_id=admin_a.id, tenant_id=tenant_a.id, role=TenantMembership.ROLE_ADMIN)
        db.session.add(membership_aa)

        # Tenant 2: Beta Industries
        tenant_b = Tenant(name='Beta Industries', slug='beta-industries')
        db.session.add(tenant_b)
        db.session.flush()

        # Tenant 2 - Owner
        owner_b = User(email='owner_b@beta.com', full_name='Owner Beta', is_active_account=True)
        owner_b.set_password('Password123!')
        db.session.add(owner_b)
        db.session.flush()

        membership_ob = TenantMembership(user_id=owner_b.id, tenant_id=tenant_b.id, role=TenantMembership.ROLE_OWNER)
        db.session.add(membership_ob)

        # Tenant 2 - Viewer
        viewer_b = User(email='viewer_b@beta.com', full_name='Viewer Beta', is_active_account=True)
        viewer_b.set_password('Password123!')
        db.session.add(viewer_b)
        db.session.flush()

        membership_vb = TenantMembership(user_id=viewer_b.id, tenant_id=tenant_b.id, role=TenantMembership.ROLE_VIEWER)
        db.session.add(membership_vb)

        db.session.commit()

        return {
            'tenant_a_id': tenant_a.id,
            'owner_a_id': owner_a.id,
            'viewer_a_id': viewer_a.id,
            'admin_a_id': admin_a.id,
            'tenant_b_id': tenant_b.id,
            'owner_b_id': owner_b.id,
            'viewer_b_id': viewer_b.id
        }
