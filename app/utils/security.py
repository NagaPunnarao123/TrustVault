from functools import wraps
import re
from flask import session, abort, redirect, url_for, flash, request
from flask_login import current_user
from werkzeug.utils import secure_filename
from app.models import TenantMembership, Document, AccessPermission
from app.audit.service import log_audit_event

def get_active_tenant_id() -> int | None:
    """
    Retrieve the current active tenant ID from session.
    If not set but user is authenticated, defaults to their first tenant membership.
    """
    if not current_user or not current_user.is_authenticated:
        return None
    
    tenant_id = session.get('active_tenant_id')
    if tenant_id:
        # Verify user is still a valid member of this tenant
        if current_user.is_tenant_member(tenant_id):
            return tenant_id
    
    # Fallback to the first available tenant membership
    first_membership = TenantMembership.query.filter_by(user_id=current_user.id).first()
    if first_membership:
        session['active_tenant_id'] = first_membership.tenant_id
        return first_membership.tenant_id
        
    return None

def set_active_tenant_id(tenant_id: int) -> bool:
    """
    Switch active tenant after validating the current user is an authorized member.
    """
    if not current_user or not current_user.is_authenticated:
        return False
    
    if current_user.is_tenant_member(tenant_id):
        session['active_tenant_id'] = tenant_id
        return True
    return False

def get_current_user_role() -> str | None:
    """Get the role of the current user in their active tenant."""
    tenant_id = get_active_tenant_id()
    if not tenant_id or not current_user or not current_user.is_authenticated:
        return None
    return current_user.get_role_in_tenant(tenant_id)

def require_role(*roles):
    """
    Decorator enforcing that the current user has one of the required roles
    within the active tenant context.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login', next=request.url))
            
            tenant_id = get_active_tenant_id()
            if not tenant_id:
                flash('You do not belong to any active organization.', 'danger')
                return redirect(url_for('auth.login'))
            
            user_role = current_user.get_role_in_tenant(tenant_id)
            if not user_role or user_role not in roles:
                # Log security audit violation
                log_audit_event(
                    action='ACCESS_DENIED',
                    resource_type='ENDPOINT',
                    resource_id=request.endpoint,
                    status='DENIED',
                    details=f"User role '{user_role}' does not satisfy required roles: {roles}",
                    tenant_id=tenant_id
                )
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def can_access_document(document: Document, user, action: str = 'VIEW') -> tuple[bool, str]:
    """
    Core authorization engine for all document interactions.
    Enforces multi-tenancy isolation and RBAC server-side.
    
    Actions:
      - 'VIEW' / 'DOWNLOAD': Allowed for Owner, or User with explicit AccessPermission.
      - 'DELETE': Allowed ONLY for document Owner.
      - 'SHARE' / 'REVOKE': Allowed ONLY for document Owner.
    
    Returns:
      (True, "Authorized") or (False, "Reason for denial")
    """
    if not document or document.is_deleted:
        return False, "Document does not exist or has been deleted."

    if not user or not user.is_authenticated:
        return False, "Authentication required."

    # Multi-tenancy check: strict cross-tenant boundary
    if not user.is_tenant_member(document.tenant_id):
        return False, "Tenant isolation violation: user does not belong to document's organization."

    user_role = user.get_role_in_tenant(document.tenant_id)
    is_owner = (document.owner_id == user.id)

    # 1. Owner Actions: DELETE, SHARE, REVOKE
    if action in {'DELETE', 'SHARE', 'REVOKE'}:
        if not is_owner:
            return False, f"Only the document owner can perform {action.lower()} actions."
        return True, "Authorized as document owner."

    # 2. Read Actions: VIEW, DOWNLOAD
    if action in {'VIEW', 'DOWNLOAD'}:
        # Document owner always has access
        if is_owner:
            return True, "Authorized as document owner."

        # Check explicit sharing permission
        permission = AccessPermission.query.filter_by(
            document_id=document.id,
            user_id=user.id
        ).first()

        if permission:
            return True, "Authorized via explicit document share."

        # If user is a VIEWER or non-owner without share, denied
        return False, "Access denied: document is not shared with you."

    return False, f"Unknown action: {action}"

def sanitize_filename(filename: str) -> str:
    """
    Sanitize uploaded filename to prevent directory traversal or malformed paths.
    """
    clean = secure_filename(filename)
    if not clean:
        clean = "document"
    return clean

def is_allowed_file(filename: str, allowed_extensions: set) -> bool:
    """
    Validate that the uploaded file has an allowed extension.
    """
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in allowed_extensions
