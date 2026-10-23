import pytest
from app.models import User, Tenant, TenantMembership, AuditEvent
from app.extensions import db

def test_admin_routes_restricted_to_admin_role(client, auth, seed_tenants):
    """Users with OWNER or VIEWER roles must be rejected from /admin routes with 403."""
    # 1. Test as Viewer
    auth.login(email='viewer_a@alpha.com', password='Password123!')
    assert client.get('/admin/users').status_code == 403
    assert client.get('/admin/audit-logs').status_code == 403
    auth.logout()

    # 2. Test as Owner
    auth.login(email='owner_a@alpha.com', password='Password123!')
    assert client.get('/admin/users').status_code == 403
    assert client.get('/admin/audit-logs').status_code == 403
    auth.logout()

    # 3. Test as Admin
    auth.login(email='admin_a@alpha.com', password='Password123!')
    assert client.get('/admin/users').status_code == 200
    assert client.get('/admin/audit-logs').status_code == 200


def test_cli_bootstrap_admin(cli_runner, app):
    """
    Test the safe administrator bootstrap CLI command (`flask bootstrap-admin`).
    Verifies that administrative accounts can be safely initialized via environment
    without exposing a public registration route.
    """
    result = cli_runner.invoke(args=[
        'bootstrap-admin',
        '--email', 'bootstrapped_admin@corp.local',
        '--password', 'VeryStrongSecret123!',
        '--tenant', 'Bootstrapped Corp'
    ])

    assert result.exit_code == 0
    assert 'Administrator bootstrap complete.' in result.output

    with app.app_context():
        admin = User.query.filter_by(email='bootstrapped_admin@corp.local').first()
        assert admin is not None
        assert admin.check_password('VeryStrongSecret123!') is True

        tenant = Tenant.query.filter_by(name='Bootstrapped Corp').first()
        assert tenant is not None

        membership = TenantMembership.query.filter_by(user_id=admin.id, tenant_id=tenant.id).first()
        assert membership is not None
        assert membership.role == TenantMembership.ROLE_ADMIN


def test_admin_add_member_and_toggle_status(client, auth, seed_tenants, app):
    """Admin can add new members with roles and toggle account activation status."""
    auth.login(email='admin_a@alpha.com', password='Password123!')

    # Add a new member as VIEWER
    add_resp = client.post('/admin/users', data={
        'full_name': 'New Recruit',
        'email': 'recruit@alpha.com',
        'role': 'VIEWER'
    }, follow_redirects=True)

    assert add_resp.status_code == 200
    assert b'User added successfully' in add_resp.data

    with app.app_context():
        recruit = User.query.filter_by(email='recruit@alpha.com').first()
        assert recruit is not None
        recruit_id = recruit.id
        membership = TenantMembership.query.filter_by(
            user_id=recruit.id, tenant_id=seed_tenants['tenant_a_id']
        ).first()
        assert membership.role == TenantMembership.ROLE_VIEWER

    # Toggle status (deactivate)
    toggle_resp = client.post(f'/admin/users/{recruit_id}/toggle-status', follow_redirects=True)
    assert b'account has been deactivated' in toggle_resp.data

    with app.app_context():
        check_user = db.session.get(User, recruit_id)
        assert check_user.is_active_account is False


def test_admin_cannot_deactivate_self(client, auth, seed_tenants):
    """Admin cannot deactivate their own account."""
    auth.login(email='admin_a@alpha.com', password='Password123!')
    admin_id = seed_tenants['admin_a_id']

    resp = client.post(f'/admin/users/{admin_id}/toggle-status', follow_redirects=True)
    assert b'cannot deactivate your own' in resp.data
