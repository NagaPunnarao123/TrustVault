from datetime import datetime, timezone, timedelta
import re
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db

class Tenant(db.Model):
    """
    Tenant (Company / Organization) model for multi-tenancy.
    All business data (documents, memberships, permissions, audit events)
    is strictly partitioned by tenant_id.
    """
    __tablename__ = 'tenants'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(80), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    memberships = db.relationship('TenantMembership', back_populates='tenant', cascade='all, delete-orphan')
    documents = db.relationship('Document', back_populates='tenant', cascade='all, delete-orphan')
    audit_events = db.relationship('AuditEvent', back_populates='tenant', cascade='all, delete-orphan')

    @staticmethod
    def generate_slug(name: str) -> str:
        """Convert a name into a URL-friendly lowercase slug."""
        clean = re.sub(r'[^a-zA-Z0-9\s-]', '', name).strip().lower()
        return re.sub(r'[\s-]+', '-', clean)

    def __repr__(self):
        return f'<Tenant {self.id}: {self.name}>'


class User(UserMixin, db.Model):
    """
    User model representing an authenticated identity.
    A user can belong to one or more tenants through TenantMembership.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    is_active_account = db.Column(db.Boolean, default=True, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    memberships = db.relationship('TenantMembership', back_populates='user', cascade='all, delete-orphan')
    owned_documents = db.relationship('Document', back_populates='owner', foreign_keys='Document.owner_id')
    received_permissions = db.relationship('AccessPermission', back_populates='user', foreign_keys='AccessPermission.user_id')
    audit_events = db.relationship('AuditEvent', back_populates='user')

    # Flask-Login interface override
    @property
    def is_active(self):
        return self.is_active_account

    def set_password(self, password: str) -> None:
        """Hash and store a secure password using pbkdf2:sha256 / scrypt."""
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify the password against the stored hash."""
        if not self.password_hash or not password:
            return False
        return check_password_hash(self.password_hash, password)

    def is_locked(self) -> bool:
        """Check if the account is currently locked due to repeated failed login attempts."""
        if self.locked_until:
            now_utc = datetime.now(timezone.utc)
            locked_time = self.locked_until if self.locked_until.tzinfo else self.locked_until.replace(tzinfo=timezone.utc)
            if now_utc < locked_time:
                return True
            # Lockout period expired: auto-reset
            self.locked_until = None
            self.failed_login_attempts = 0
        return False

    def record_failed_login(self, max_attempts: int = 5, lockout_minutes: int = 15) -> bool:
        """
        Record a failed authentication attempt.
        Locks the account for `lockout_minutes` if `max_attempts` is reached.
        Returns True if the account became locked, False otherwise.
        """
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
            return True
        return False

    def reset_failed_logins(self) -> None:
        """Reset failed login counters upon successful authentication."""
        self.failed_login_attempts = 0
        self.locked_until = None

    def get_role_in_tenant(self, tenant_id: int):
        """Retrieve user's role (ADMIN, OWNER, VIEWER) for a specific tenant."""
        membership = TenantMembership.query.filter_by(
            user_id=self.id, tenant_id=tenant_id
        ).first()
        return membership.role if membership else None

    def is_tenant_member(self, tenant_id: int) -> bool:
        """Check if user is a member of the given tenant."""
        return self.get_role_in_tenant(tenant_id) is not None

    def __repr__(self):
        return f'<User {self.id}: {self.email}>'


class TenantMembership(db.Model):
    """
    Explicit membership and role assignment linking a User to a Tenant.
    Roles:
      - ADMIN: Manages tenant users and reviews audit logs.
      - OWNER: Uploads, manages, shares, revokes, and deletes own documents.
      - VIEWER: Read-only access to documents explicitly shared with them.
    """
    __tablename__ = 'tenant_memberships'
    __table_args__ = (
        db.UniqueConstraint('user_id', 'tenant_id', name='uq_user_tenant'),
    )

    ROLE_ADMIN = 'ADMIN'
    ROLE_OWNER = 'OWNER'
    ROLE_VIEWER = 'VIEWER'
    VALID_ROLES = {ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    user = db.relationship('User', back_populates='memberships')
    tenant = db.relationship('Tenant', back_populates='memberships')

    def __repr__(self):
        return f'<TenantMembership user={self.user_id} tenant={self.tenant_id} role={self.role}>'


class Document(db.Model):
    """
    Metadata for uploaded documents.
    Physical files are stored on private disk outside static roots under storage_filename (UUID).
    """
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    storage_filename = db.Column(db.String(64), unique=True, nullable=False, index=True)
    file_type = db.Column(db.String(50), nullable=False)
    file_size_bytes = db.Column(db.Integer, nullable=False)
    sha256_checksum = db.Column(db.String(64), nullable=True)
    category = db.Column(db.String(50), default='General', nullable=False)
    description = db.Column(db.String(500), default='', nullable=False)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False, index=True)

    # Relationships
    tenant = db.relationship('Tenant', back_populates='documents')
    owner = db.relationship('User', back_populates='owned_documents', foreign_keys=[owner_id])
    permissions = db.relationship('AccessPermission', back_populates='document', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Document {self.id}: {self.original_filename} (Tenant {self.tenant_id})>'


class AccessPermission(db.Model):
    """
    Permission record allowing a user within the same tenant to access a document.
    Owners grant or revoke permissions. Revocation takes effect immediately for future downloads.
    """
    __tablename__ = 'access_permissions'
    __table_args__ = (
        db.UniqueConstraint('document_id', 'user_id', name='uq_doc_user_permission'),
    )

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    granted_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    granted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    document = db.relationship('Document', back_populates='permissions')
    user = db.relationship('User', back_populates='received_permissions', foreign_keys=[user_id])
    granted_by = db.relationship('User', foreign_keys=[granted_by_id])

    def __repr__(self):
        return f'<AccessPermission doc={self.document_id} user={self.user_id}>'


class AuditEvent(db.Model):
    """
    Immutable audit trail recording all security-relevant operations.
    Tamper notice: While database rows are append-only within application logic,
    database logs are not inherently tamper-proof against direct administrative
    database modifications or server root compromise.
    """
    __tablename__ = 'audit_events'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id', ondelete='SET NULL'), nullable=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    action = db.Column(db.String(50), nullable=False, index=True)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.String(64), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    status = db.Column(db.String(20), nullable=False)  # SUCCESS, FAILURE, DENIED
    details = db.Column(db.Text, default='', nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    tenant = db.relationship('Tenant', back_populates='audit_events')
    user = db.relationship('User', back_populates='audit_events')

    def __repr__(self):
        return f'<AuditEvent {self.id}: {self.action} [{self.status}]>'
