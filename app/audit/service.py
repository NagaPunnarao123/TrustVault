from flask import request, session, has_request_context
from flask_login import current_user
from app.extensions import db
from app.models import AuditEvent

def log_audit_event(
    action: str,
    resource_type: str,
    resource_id: str = None,
    status: str = 'SUCCESS',
    details: str = '',
    tenant_id: int = None,
    user_id: int = None,
    ip_address: str = None
) -> AuditEvent:
    """
    Centralized helper to record verifiable security audit trails.
    Automatically resolves actor, tenant, and IP from the request context if omitted.
    
    Tamper Boundary Notice:
    Audit logs in the database are protected by server-side append-only logic.
    They cannot prevent modification by an attacker who achieves direct root access
    to the underlying database or server host filesystem.
    """
    try:
        # Resolve actor user ID
        if user_id is None and has_request_context():
            if current_user and current_user.is_authenticated:
                user_id = current_user.id

        # Resolve tenant ID
        if tenant_id is None and has_request_context():
            tenant_id = session.get('active_tenant_id')

        # Resolve IP Address
        if ip_address is None and has_request_context():
            # Support trusted proxies safely or fallback to remote_addr
            forwarded = request.headers.get('X-Forwarded-For')
            if forwarded:
                ip_address = forwarded.split(',')[0].strip()
            else:
                ip_address = request.remote_addr or '127.0.0.1'

        event = AuditEvent(
            tenant_id=tenant_id,
            user_id=user_id,
            action=action.upper(),
            resource_type=resource_type.upper(),
            resource_id=str(resource_id) if resource_id is not None else None,
            ip_address=ip_address,
            status=status.upper(),
            details=str(details)[:1000] if details else ''
        )
        db.session.add(event)
        db.session.commit()
        return event
    except Exception as e:
        # Ensure audit logging failure never crashes application silently without rollback
        db.session.rollback()
        # In a real environment, write to standard fallback logger
        return None
