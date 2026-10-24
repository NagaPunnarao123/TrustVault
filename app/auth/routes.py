from datetime import datetime, timezone
from flask import render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse
from app.auth import auth_bp
from app.auth.forms import LoginForm, RegisterForm, ChangePasswordForm
from app.models import User, Tenant, TenantMembership
from app.extensions import db
from app.audit.service import log_audit_event
from app.utils.security import set_active_tenant_id, get_active_tenant_id

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticate existing users."""
    if current_user.is_authenticated:
        return redirect(url_for('documents.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user:
            # 1. Check account lockout state
            if user.is_locked():
                now_utc = datetime.now(timezone.utc)
                locked_time = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
                remaining_mins = max(1, int((locked_time - now_utc).total_seconds() / 60) + 1)
                
                log_audit_event(
                    action='LOGIN_BLOCKED',
                    resource_type='USER',
                    resource_id=str(user.id),
                    status='DENIED',
                    details=f"Login attempt blocked: account is temporarily locked ({remaining_mins}m remaining)",
                    user_id=user.id
                )
                flash(f'Account is temporarily locked due to multiple failed login attempts. Please try again in {remaining_mins} minute(s).', 'danger')
                return render_template('auth/login.html', form=form)

            # 2. Check credentials
            if user.check_password(password):
                if not user.is_active:
                    log_audit_event(
                        action='LOGIN_FAILURE',
                        resource_type='USER',
                        resource_id=str(user.id),
                        status='DENIED',
                        details='Account is deactivated',
                        user_id=user.id
                    )
                    flash('Your account has been deactivated. Please contact your administrator.', 'danger')
                    return render_template('auth/login.html', form=form)

                # Reset lockout counter on success
                user.reset_failed_logins()
                db.session.commit()

                # Session fixation prevention: clear old session tokens before establishing identity
                session.clear()

                login_user(user, remember=form.remember_me.data)

                # Determine and set active tenant
                membership = TenantMembership.query.filter_by(user_id=user.id).first()
                if membership:
                    session['active_tenant_id'] = membership.tenant_id

                log_audit_event(
                    action='LOGIN_SUCCESS',
                    resource_type='USER',
                    resource_id=str(user.id),
                    status='SUCCESS',
                    details='User successfully logged in',
                    user_id=user.id,
                    tenant_id=membership.tenant_id if membership else None
                )

                flash(f'Welcome back, {user.full_name}!', 'success')
                next_page = request.args.get('next')
                # Prevent Open Redirect vulnerability
                if next_page and urlparse(next_page).netloc == '':
                    return redirect(next_page)
                return redirect(url_for('documents.dashboard'))
            else:
                # Password incorrect: increment failure counter
                is_now_locked = user.record_failed_login(max_attempts=5, lockout_minutes=15)
                db.session.commit()

                if is_now_locked:
                    log_audit_event(
                        action='ACCOUNT_LOCKED',
                        resource_type='USER',
                        resource_id=str(user.id),
                        status='WARNING',
                        details='Account locked for 15 minutes after 5 consecutive failed login attempts',
                        user_id=user.id
                    )
                    flash('Invalid email address or password. Your account has been temporarily locked for 15 minutes due to multiple failed attempts.', 'danger')
                else:
                    attempts_left = 5 - user.failed_login_attempts
                    log_audit_event(
                        action='LOGIN_FAILURE',
                        resource_type='USER',
                        resource_id=str(user.id),
                        status='FAILURE',
                        details=f"Invalid password attempt ({attempts_left} attempts remaining before temporary lockout)",
                        user_id=user.id
                    )
                    flash(f'Invalid email address or password. ({attempts_left} attempt(s) remaining before temporary lockout)', 'danger')
        else:
            log_audit_event(
                action='LOGIN_FAILURE',
                resource_type='AUTH',
                resource_id=email,
                status='FAILURE',
                details='Invalid email address'
            )
            flash('Invalid email address or password.', 'danger')

    return render_template('auth/login.html', form=form)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    Self-service registration.
    Initializes a new Tenant/Organization with the user as the initial OWNER.
    Administrator roles cannot be registered through this route.
    """
    if current_user.is_authenticated:
        return redirect(url_for('documents.dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        full_name = form.full_name.data.strip()
        org_name = form.organization_name.data.strip()
        password = form.password.data

        # Generate unique tenant slug
        base_slug = Tenant.generate_slug(org_name)
        if not base_slug:
            base_slug = 'org'
        slug = base_slug
        counter = 1
        while Tenant.query.filter_by(slug=slug).first():
            slug = f"{base_slug}-{counter}"
            counter += 1

        try:
            # 1. Create Tenant
            tenant = Tenant(name=org_name, slug=slug)
            db.session.add(tenant)
            db.session.flush()  # Obtain tenant.id

            # 2. Create User
            user = User(
                email=email,
                full_name=full_name,
                is_active_account=True
            )
            user.set_password(password)
            db.session.add(user)
            db.session.flush()  # Obtain user.id

            # 3. Assign user as OWNER of their new organization
            membership = TenantMembership(
                user_id=user.id,
                tenant_id=tenant.id,
                role=TenantMembership.ROLE_OWNER
            )
            db.session.add(membership)
            db.session.commit()

            log_audit_event(
                action='REGISTER_SUCCESS',
                resource_type='USER',
                resource_id=str(user.id),
                status='SUCCESS',
                details=f"User registered with organization '{tenant.name}' as OWNER",
                user_id=user.id,
                tenant_id=tenant.id
            )

            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')

    return render_template('auth/register.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    """Log out the current user and invalidate the session."""
    active_tenant_id = session.get('active_tenant_id')
    user_id = current_user.id
    
    log_audit_event(
        action='LOGOUT',
        resource_type='USER',
        resource_id=str(user_id),
        status='SUCCESS',
        details='User logged out',
        user_id=user_id,
        tenant_id=active_tenant_id
    )

    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile and secure password change."""
    form = ChangePasswordForm()
    active_tenant_id = get_active_tenant_id()
    active_tenant = db.session.get(Tenant, active_tenant_id) if active_tenant_id else None
    user_role = current_user.get_role_in_tenant(active_tenant_id) if active_tenant_id else None

    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Current password verification failed.', 'danger')
        else:
            current_user.set_password(form.new_password.data)
            db.session.commit()

            log_audit_event(
                action='PASSWORD_CHANGE',
                resource_type='USER',
                resource_id=str(current_user.id),
                status='SUCCESS',
                details='Password updated successfully by user',
                user_id=current_user.id,
                tenant_id=active_tenant_id
            )
            flash('Your password has been updated successfully.', 'success')
            return redirect(url_for('auth.profile'))

    return render_template(
        'auth/profile.html',
        form=form,
        active_tenant=active_tenant,
        user_role=user_role
    )


@auth_bp.route('/switch-tenant/<int:tenant_id>', methods=['POST'])
@login_required
def switch_tenant(tenant_id):
    """Switch the current active tenant context."""
    if set_active_tenant_id(tenant_id):
        flash('Switched active organization context.', 'success')
    else:
        flash('Access denied: You are not a member of that organization.', 'danger')
    return redirect(url_for('documents.dashboard'))
