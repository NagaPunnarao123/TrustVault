from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
import secrets
from app.admin import admin_bp
from app.admin.forms import AddTenantUserForm
from app.models import TenantMembership, User, AuditEvent, Tenant
from app.extensions import db
from app.audit.service import log_audit_event
from app.utils.security import get_active_tenant_id, require_role

@admin_bp.route('/users', methods=['GET', 'POST'])
@login_required
@require_role(TenantMembership.ROLE_ADMIN)
def users():
    """
    Manage organization members.
    View members, assign roles (ADMIN, OWNER, VIEWER), and add members.
    """
    tenant_id = get_active_tenant_id()
    tenant = db.session.get(Tenant, tenant_id)

    form = AddTenantUserForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        full_name = form.full_name.data.strip()
        role = form.role.data

        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        temp_password = None
        if not user:
            # Create user with a secure random initial password
            temp_password = secrets.token_urlsafe(10)
            user = User(
                email=email,
                full_name=full_name,
                is_active_account=True
            )
            user.set_password(temp_password)
            db.session.add(user)
            db.session.flush()

        # Check if already a member of this tenant
        existing_membership = TenantMembership.query.filter_by(
            user_id=user.id, tenant_id=tenant_id
        ).first()

        if existing_membership:
            flash(f"User '{email}' is already a member with role '{existing_membership.role}'.", 'warning')
        else:
            membership = TenantMembership(
                user_id=user.id,
                tenant_id=tenant_id,
                role=role
            )
            db.session.add(membership)
            db.session.commit()

            log_audit_event(
                action='ADMIN_ACTION',
                resource_type='MEMBERSHIP',
                resource_id=str(user.id),
                status='SUCCESS',
                details=f"Added member {email} with role {role} to tenant {tenant.name}",
                tenant_id=tenant_id,
                user_id=current_user.id
            )

            if temp_password:
                flash(f"User added successfully! Initial temporary password: {temp_password}", 'success')
            else:
                flash(f"Existing user '{email}' added to organization as {role}.", 'success')

        return redirect(url_for('admin.users'))

    # Query members of current tenant
    memberships = TenantMembership.query.filter_by(tenant_id=tenant_id).all()
    return render_template(
        'admin/users.html',
        tenant=tenant,
        form=form,
        memberships=memberships
    )


@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@require_role(TenantMembership.ROLE_ADMIN)
def toggle_user_status(user_id):
    """
    Activate or deactivate a user account.
    Admins cannot deactivate their own account.
    """
    tenant_id = get_active_tenant_id()
    if user_id == current_user.id:
        flash("You cannot deactivate your own administrative account.", 'warning')
        return redirect(url_for('admin.users'))

    # Verify target belongs to the same tenant
    membership = TenantMembership.query.filter_by(user_id=user_id, tenant_id=tenant_id).first()
    if not membership:
        abort(404)

    target_user = db.get_or_404(User, user_id)
    target_user.is_active_account = not target_user.is_active_account
    db.session.commit()

    action_label = "activated" if target_user.is_active_account else "deactivated"
    log_audit_event(
        action='ADMIN_ACTION',
        resource_type='USER',
        resource_id=str(user_id),
        status='SUCCESS',
        details=f"Admin {action_label} user account '{target_user.email}'",
        tenant_id=tenant_id,
        user_id=current_user.id
    )

    flash(f"User '{target_user.email}' account has been {action_label}.", 'info')
    return redirect(url_for('admin.users'))


@admin_bp.route('/audit-logs')
@login_required
@require_role(TenantMembership.ROLE_ADMIN)
def audit_logs():
    """
    Review organization audit events.
    Strictly restricted to organization ADMINs and scoped to current tenant.
    """
    tenant_id = get_active_tenant_id()
    tenant = db.session.get(Tenant, tenant_id)

    action_filter = request.args.get('action', '').strip()
    status_filter = request.args.get('status', '').strip()

    query = AuditEvent.query.filter_by(tenant_id=tenant_id)

    if action_filter and action_filter != 'ALL':
        query = query.filter(AuditEvent.action == action_filter)

    if status_filter and status_filter != 'ALL':
        query = query.filter(AuditEvent.status == status_filter)

    events = query.order_by(AuditEvent.created_at.desc()).limit(100).all()

    # Log review of audit records
    log_audit_event(
        action='ADMIN_ACTION',
        resource_type='AUDIT_LOGS',
        resource_id=str(tenant_id),
        status='SUCCESS',
        details="Admin reviewed organization audit logs",
        tenant_id=tenant_id,
        user_id=current_user.id
    )

    actions = ['ALL', 'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'LOGOUT', 'UPLOAD_DOCUMENT',
               'DOWNLOAD_DOCUMENT', 'DELETE_DOCUMENT', 'GRANT_PERMISSION',
               'REVOKE_PERMISSION', 'ACCESS_DENIED', 'ADMIN_ACTION']
    statuses = ['ALL', 'SUCCESS', 'FAILURE', 'DENIED']

    return render_template(
        'admin/audit_logs.html',
        tenant=tenant,
        events=events,
        actions=actions,
        statuses=statuses,
        action_filter=action_filter,
        status_filter=status_filter
    )
