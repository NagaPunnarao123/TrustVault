
import os
import click
from pathlib import Path
from flask import Flask, render_template, session, redirect, url_for
from flask_login import current_user
from app.config import config_by_name, DevelopmentConfig
from app.extensions import db, login_manager, csrf
from app.models import User, Tenant, TenantMembership


def create_app(config_class=None):
    """Application factory for TrustVault."""
    app = Flask(__name__)

    if config_class is None:
        env_name = os.environ.get("FLASK_ENV", "development").lower()
        config_class = config_by_name.get(env_name, DevelopmentConfig)

    app.config.from_object(config_class)

    # Validate production configuration and prepare PostgreSQL URL
    if isinstance(config_class, type) and config_class.__name__ == "ProductionConfig":
        config_class.init_app(app)

        database_url = app.config["SQLALCHEMY_DATABASE_URI"]

        if database_url.startswith("postgres://"):
            database_url = database_url.replace(
                "postgres://", "postgresql+psycopg://", 1
            )
        elif database_url.startswith("postgresql://"):
            database_url = database_url.replace(
                "postgresql://", "postgresql+psycopg://", 1
            )

        app.config["SQLALCHEMY_DATABASE_URI"] = database_url

    # Ensure instance and upload folders exist
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Register blueprints
    from app.auth import auth_bp
    from app.documents import documents_bp
    from app.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(admin_bp)

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("documents.dashboard"))
        return redirect(url_for("auth.login"))

    # Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), payment=()"
        )

        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data:; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "frame-ancestors 'none';"
            )
        return response

    # Template context
    @app.context_processor
    def inject_context():
        if current_user.is_authenticated:
            tenant_id = session.get("active_tenant_id")
            active_tenant = (
                db.session.get(Tenant, tenant_id) if tenant_id else None
            )
            user_role = (
                current_user.get_role_in_tenant(tenant_id)
                if tenant_id else None
            )
            user_tenants = [m.tenant for m in current_user.memberships]

            return {
                "active_tenant": active_tenant,
                "user_role": user_role,
                "user_tenants": user_tenants,
            }

        return {
            "active_tenant": None,
            "user_role": None,
            "user_tenants": [],
        }

    # Error handlers
    @app.errorhandler(400)
    def bad_request(e):
        return render_template("errors/400.html", error=e), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html", error=e), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html", error=e), 404

    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        return render_template("errors/500.html", error=e), 500

    # Initialize database command
    @app.cli.command("init-db")
    def init_db():
        from app.utils.migrations import apply_db_migrations
        apply_db_migrations()
        click.echo("Initialized database schema.")

    # Administrator bootstrap command
    @app.cli.command("bootstrap-admin")
    @click.option("--email", default=None, help="Admin email address")
    @click.option("--password", default=None, help="Admin password")
    @click.option("--tenant", default=None, help="Organization/Tenant name")
    def bootstrap_admin(email, password, tenant):
        from app.utils.migrations import apply_db_migrations
        apply_db_migrations()

        admin_email = (
            email or os.environ.get("ADMIN_EMAIL", "admin@trustvault.local")
        ).strip().lower()
        admin_pass = password or os.environ.get("ADMIN_PASSWORD")
        tenant_name = tenant or os.environ.get(
            "ADMIN_TENANT_NAME", "TrustVault Security Corp"
        )

        if not admin_pass:
            raise click.ClickException(
                "Set ADMIN_PASSWORD before creating the administrator."
            )

        slug = Tenant.generate_slug(tenant_name)
        org = Tenant.query.filter_by(slug=slug).first()

        if not org:
            org = Tenant(name=tenant_name, slug=slug)
            db.session.add(org)
            db.session.flush()
            click.echo(f"Created organization '{tenant_name}'.")

        user = User.query.filter_by(email=admin_email).first()

        if not user:
            user = User(
                email=admin_email,
                full_name="System Administrator",
                is_active_account=True,
            )
            user.set_password(admin_pass)
            db.session.add(user)
            db.session.flush()
            click.echo(f"Created administrator '{admin_email}'.")
        else:
            user.set_password(admin_pass)
            click.echo(f"Updated administrator password for '{admin_email}'.")

        membership = TenantMembership.query.filter_by(
            user_id=user.id, tenant_id=org.id
        ).first()

        if not membership:
            membership = TenantMembership(
                user_id=user.id,
                tenant_id=org.id,
                role=TenantMembership.ROLE_ADMIN,
            )
            db.session.add(membership)
        else:
            membership.role = TenantMembership.ROLE_ADMIN

        db.session.commit()
        click.echo("Administrator bootstrap complete.")

    return app
