import pytest
from app.models import User, Tenant, TenantMembership
from app.extensions import db

def test_password_hashing():
    """Verify passwords are secure hashes and never stored in plaintext."""
    user = User(email='security@example.com', full_name='Security Officer')
    user.set_password('SuperSecure123!')

    # Ensure hash is generated and not plaintext
    assert user.password_hash != 'SuperSecure123!'
    assert len(user.password_hash) > 20
    assert user.check_password('SuperSecure123!') is True
    assert user.check_password('WrongPassword!') is False

    # Password length boundary
    with pytest.raises(ValueError):
        user.set_password('short')


def test_registration_creates_tenant_and_owner(client, app):
    """
    Verify self-service registration creates an isolated Tenant,
    creates the User, and assigns the user as initial OWNER.
    """
    response = client.post('/auth/register', data={
        'full_name': 'Alice Wonder',
        'email': 'alice@wonderland.com',
        'organization_name': 'Wonderland Tech',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Account created successfully' in response.data

    with app.app_context():
        user = User.query.filter_by(email='alice@wonderland.com').first()
        assert user is not None
        assert user.full_name == 'Alice Wonder'

        tenant = Tenant.query.filter_by(name='Wonderland Tech').first()
        assert tenant is not None
        assert tenant.slug == 'wonderland-tech'

        membership = TenantMembership.query.filter_by(user_id=user.id, tenant_id=tenant.id).first()
        assert membership is not None
        assert membership.role == TenantMembership.ROLE_OWNER


def test_registration_duplicate_email_rejected(client, auth):
    """Verify duplicate email registration is rejected with a validation error."""
    auth.register(email='duplicate@test.com', organization_name='Org One')
    response = auth.register(email='duplicate@test.com', organization_name='Org Two')

    assert b'already exists' in response.data


def test_login_success_and_logout(client, auth):
    """Verify authenticating with valid credentials establishes session, and logout clears it."""
    auth.register(email='bob@builder.com', password='HammerTime123!', full_name='Bob', organization_name='Builder Co')

    # Successful login
    response = auth.login(email='bob@builder.com', password='HammerTime123!')
    assert response.status_code == 200
    assert b'Welcome back, Bob!' in response.data

    # Access protected dashboard
    dash_resp = client.get('/documents/dashboard')
    assert dash_resp.status_code == 200
    assert b'Builder Co' in dash_resp.data

    # Logout
    logout_resp = auth.logout()
    assert b'You have been logged out' in logout_resp.data

    # After logout, accessing dashboard redirects to login
    dash_after = client.get('/documents/dashboard', follow_redirects=False)
    assert dash_after.status_code == 302
    assert '/auth/login' in dash_after.headers['Location']


def test_login_invalid_password(client, auth):
    """Verify login fails on wrong password."""
    auth.register(email='charlie@check.com', password='RightPassword123!')
    response = auth.login(email='charlie@check.com', password='WrongPassword999!')

    assert response.status_code == 200
    assert b'Invalid email address or password' in response.data


def test_deactivated_user_cannot_login(client, auth, app):
    """Verify deactivated accounts are rejected during authentication."""
    auth.register(email='inactive@company.com', password='Password123!')

    with app.app_context():
        user = User.query.filter_by(email='inactive@company.com').first()
        user.is_active_account = False
        db.session.commit()

    response = auth.login(email='inactive@company.com', password='Password123!')
    assert b'account has been deactivated' in response.data


def test_anonymous_user_redirected_to_login(client):
    """Verify unauthenticated users cannot access protected document routes."""
    routes_to_test = [
        '/documents/dashboard',
        '/documents/my-documents',
        '/documents/shared-with-me',
        '/documents/upload',
        '/auth/profile',
        '/admin/users',
        '/admin/audit-logs'
    ]

    for route in routes_to_test:
        resp = client.get(route, follow_redirects=False)
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']
