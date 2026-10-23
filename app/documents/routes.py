import os
from flask import (
    render_template, redirect, url_for, flash, request,
    send_from_directory, abort, current_app
)
from flask_login import login_required, current_user
from app.documents import documents_bp
from app.documents.forms import DocumentUploadForm, ShareDocumentForm
from app.models import Document, AccessPermission, TenantMembership, User, Tenant
from app.extensions import db
from app.audit.service import log_audit_event
from app.utils.security import (
    get_active_tenant_id, require_role, can_access_document,
    sanitize_filename, is_allowed_file
)
from app.utils.storage import (
    generate_storage_filename, save_uploaded_file, delete_stored_file
)

@documents_bp.route('/')
@documents_bp.route('/dashboard')
@login_required
def dashboard():
    """
    Main dashboard showing document overview, recent activity, and quick filters.
    All data is strictly scoped to the active tenant.
    """
    tenant_id = get_active_tenant_id()
    if not tenant_id:
        flash('Please select or create an organization.', 'warning')
        return redirect(url_for('auth.login'))

    user_role = current_user.get_role_in_tenant(tenant_id)
    tenant = db.session.get(Tenant, tenant_id)

    # Scoped document queries
    my_docs_count = Document.query.filter_by(
        tenant_id=tenant_id, owner_id=current_user.id, is_deleted=False
    ).count()

    shared_query = Document.query.join(AccessPermission).filter(
        Document.tenant_id == tenant_id,
        Document.is_deleted == False,
        AccessPermission.user_id == current_user.id
    )
    shared_docs_count = shared_query.count()

    # Recent accessible documents
    if user_role == TenantMembership.ROLE_VIEWER:
        recent_docs = shared_query.order_by(Document.uploaded_at.desc()).limit(10).all()
    else:
        # OWNER / ADMIN can see their own documents plus shared documents
        recent_docs = Document.query.filter(
            Document.tenant_id == tenant_id,
            Document.is_deleted == False,
            (Document.owner_id == current_user.id) | (
                Document.id.in_(
                    db.session.query(AccessPermission.document_id).filter_by(user_id=current_user.id)
                )
            )
        ).order_by(Document.uploaded_at.desc()).limit(10).all()

    return render_template(
        'documents/dashboard.html',
        tenant=tenant,
        user_role=user_role,
        my_docs_count=my_docs_count,
        shared_docs_count=shared_docs_count,
        recent_docs=recent_docs
    )


@documents_bp.route('/my-documents')
@login_required
def my_documents():
    """List documents uploaded by the current user within the active tenant."""
    tenant_id = get_active_tenant_id()
    user_role = current_user.get_role_in_tenant(tenant_id)

    # Search & Category Filters
    search_query = request.args.get('q', '').strip()
    category_filter = request.args.get('category', '').strip()

    query = Document.query.filter_by(
        tenant_id=tenant_id, owner_id=current_user.id, is_deleted=False
    )

    if search_query:
        query = query.filter(
            (Document.original_filename.ilike(f'%{search_query}%')) |
            (Document.description.ilike(f'%{search_query}%'))
        )

    if category_filter and category_filter != 'All':
        query = query.filter(Document.category == category_filter)

    documents = query.order_by(Document.uploaded_at.desc()).all()
    categories = ['All', 'General', 'Financial', 'Legal', 'Technical', 'HR', 'Confidential']

    return render_template(
        'documents/my_documents.html',
        documents=documents,
        user_role=user_role,
        search_query=search_query,
        category_filter=category_filter,
        categories=categories
    )


@documents_bp.route('/shared-with-me')
@login_required
def shared_with_me():
    """List documents explicitly shared with the current user in the active tenant."""
    tenant_id = get_active_tenant_id()
    user_role = current_user.get_role_in_tenant(tenant_id)

    search_query = request.args.get('q', '').strip()
    category_filter = request.args.get('category', '').strip()

    query = Document.query.join(AccessPermission).filter(
        Document.tenant_id == tenant_id,
        Document.is_deleted == False,
        AccessPermission.user_id == current_user.id
    )

    if search_query:
        query = query.filter(
            (Document.original_filename.ilike(f'%{search_query}%')) |
            (Document.description.ilike(f'%{search_query}%'))
        )

    if category_filter and category_filter != 'All':
        query = query.filter(Document.category == category_filter)

    documents = query.order_by(Document.uploaded_at.desc()).all()
    categories = ['All', 'General', 'Financial', 'Legal', 'Technical', 'HR', 'Confidential']

    return render_template(
        'documents/shared_with_me.html',
        documents=documents,
        user_role=user_role,
        search_query=search_query,
        category_filter=category_filter,
        categories=categories
    )


@documents_bp.route('/upload', methods=['GET', 'POST'])
@login_required
@require_role(TenantMembership.ROLE_OWNER)
def upload():
    """
    Upload a document. Allowed ONLY for users with the OWNER role.
    Files are stored privately outside web roots under random UUID names.
    Note: Malware scanning is not currently implemented; files are isolated and validated by extension and size.
    """
    tenant_id = get_active_tenant_id()
    form = DocumentUploadForm()

    if form.validate_on_submit():
        uploaded_file = form.file.data
        raw_filename = uploaded_file.filename

        if not raw_filename or not is_allowed_file(raw_filename, current_app.config['ALLOWED_EXTENSIONS']):
            flash('Disallowed file type. Permitted: PDF, DOCX, TXT, PNG, JPG, CSV, XLSX.', 'danger')
            return render_template('documents/upload.html', form=form)

        safe_original_name = sanitize_filename(raw_filename)
        storage_filename = generate_storage_filename(safe_original_name)
        ext = safe_original_name.rsplit('.', 1)[1].lower() if '.' in safe_original_name else 'bin'

        try:
            file_size, _ = save_uploaded_file(
                uploaded_file,
                current_app.config['UPLOAD_FOLDER'],
                storage_filename
            )

            # Record document metadata in database
            document = Document(
                tenant_id=tenant_id,
                owner_id=current_user.id,
                original_filename=safe_original_name,
                storage_filename=storage_filename,
                file_type=ext.upper(),
                file_size_bytes=file_size,
                category=form.category.data,
                description=form.description.data.strip()
            )
            db.session.add(document)
            db.session.commit()

            log_audit_event(
                action='UPLOAD_DOCUMENT',
                resource_type='DOCUMENT',
                resource_id=str(document.id),
                status='SUCCESS',
                details=f"Uploaded '{safe_original_name}' ({file_size} bytes, type: {ext})",
                tenant_id=tenant_id,
                user_id=current_user.id
            )

            flash(f"Document '{safe_original_name}' uploaded successfully.", 'success')
            return redirect(url_for('documents.my_documents'))

        except ValueError as ve:
            flash(f"Upload rejected: {str(ve)}", 'danger')
        except Exception as e:
            db.session.rollback()
            delete_stored_file(current_app.config['UPLOAD_FOLDER'], storage_filename)
            flash('Failed to save document. Please try again.', 'danger')

    return render_template('documents/upload.html', form=form)


@documents_bp.route('/<int:doc_id>/download')
@login_required
def download(doc_id):
    """
    Download a document.
    Enforces server-side tenant isolation and authorization checks on every single request.
    Serves files strictly via send_from_directory from private storage with sanitized download names.
    """
    document = db.get_or_404(Document, doc_id)
    tenant_id = get_active_tenant_id()

    # Strict authorization engine check
    authorized, reason = can_access_document(document, current_user, action='DOWNLOAD')
    if not authorized:
        log_audit_event(
            action='ACCESS_DENIED',
            resource_type='DOCUMENT',
            resource_id=str(doc_id),
            status='DENIED',
            details=f"Download rejected: {reason}",
            tenant_id=tenant_id,
            user_id=current_user.id
        )
        abort(403)

    log_audit_event(
        action='DOWNLOAD_DOCUMENT',
        resource_type='DOCUMENT',
        resource_id=str(doc_id),
        status='SUCCESS',
        details=f"Downloaded '{document.original_filename}'",
        tenant_id=document.tenant_id,
        user_id=current_user.id
    )

    upload_dir = current_app.config['UPLOAD_FOLDER']
    return send_from_directory(
        upload_dir,
        document.storage_filename,
        as_attachment=True,
        download_name=document.original_filename
    )


@documents_bp.route('/<int:doc_id>/manage-access', methods=['GET', 'POST'])
@login_required
def manage_access(doc_id):
    """
    Manage sharing permissions for a document.
    Only the document OWNER can grant or revoke access.
    Recipients must belong to the same tenant organization.
    """
    document = db.get_or_404(Document, doc_id)
    tenant_id = get_active_tenant_id()

    authorized, reason = can_access_document(document, current_user, action='SHARE')
    if not authorized:
        log_audit_event(
            action='ACCESS_DENIED',
            resource_type='DOCUMENT',
            resource_id=str(doc_id),
            status='DENIED',
            details=f"Share management rejected: {reason}",
            tenant_id=tenant_id,
            user_id=current_user.id
        )
        abort(403)

    form = ShareDocumentForm()
    if form.validate_on_submit():
        recipient_email = form.recipient_email.data.strip().lower()

        # Check recipient exists
        recipient = User.query.filter_by(email=recipient_email).first()
        if not recipient:
            flash(f"User with email '{recipient_email}' does not exist.", 'warning')
            return redirect(url_for('documents.manage_access', doc_id=doc_id))

        # Check recipient belongs to this tenant! (Multi-tenancy isolation boundary)
        if not recipient.is_tenant_member(document.tenant_id):
            flash(f"User '{recipient_email}' is not a member of your organization. Cross-organization sharing is prohibited.", 'danger')
            return redirect(url_for('documents.manage_access', doc_id=doc_id))

        if recipient.id == document.owner_id:
            flash("You are already the owner of this document.", 'info')
            return redirect(url_for('documents.manage_access', doc_id=doc_id))

        # Check existing permission
        existing = AccessPermission.query.filter_by(
            document_id=document.id, user_id=recipient.id
        ).first()

        if existing:
            flash(f"Document is already shared with {recipient.full_name} ({recipient_email}).", 'info')
        else:
            permission = AccessPermission(
                document_id=document.id,
                user_id=recipient.id,
                granted_by_id=current_user.id
            )
            db.session.add(permission)
            db.session.commit()

            log_audit_event(
                action='GRANT_PERMISSION',
                resource_type='DOCUMENT',
                resource_id=str(document.id),
                status='SUCCESS',
                details=f"Access granted to user ID {recipient.id} ({recipient.email})",
                tenant_id=document.tenant_id,
                user_id=current_user.id
            )
            flash(f"Access granted to {recipient.full_name}.", 'success')

        return redirect(url_for('documents.manage_access', doc_id=doc_id))

    # Existing granted permissions
    permissions = AccessPermission.query.filter_by(document_id=document.id).all()
    return render_template(
        'documents/manage_access.html',
        document=document,
        form=form,
        permissions=permissions
    )


@documents_bp.route('/<int:doc_id>/revoke-access/<int:user_id>', methods=['POST'])
@login_required
def revoke_access(doc_id, user_id):
    """
    Revoke a colleague's access to a document.
    Allowed only for document owner. Revocation takes effect immediately for future downloads.
    Important: Revocation cannot recall or erase previously downloaded local copies.
    """
    document = db.get_or_404(Document, doc_id)
    tenant_id = get_active_tenant_id()

    authorized, reason = can_access_document(document, current_user, action='REVOKE')
    if not authorized:
        log_audit_event(
            action='ACCESS_DENIED',
            resource_type='DOCUMENT',
            resource_id=str(doc_id),
            status='DENIED',
            details=f"Revocation rejected: {reason}",
            tenant_id=tenant_id,
            user_id=current_user.id
        )
        abort(403)

    permission = AccessPermission.query.filter_by(
        document_id=document.id, user_id=user_id
    ).first()

    if permission:
        target_user = db.session.get(User, user_id)
        db.session.delete(permission)
        db.session.commit()

        log_audit_event(
            action='REVOKE_PERMISSION',
            resource_type='DOCUMENT',
            resource_id=str(document.id),
            status='SUCCESS',
            details=f"Access revoked for user ID {user_id} ({target_user.email if target_user else 'Unknown'})",
            tenant_id=document.tenant_id,
            user_id=current_user.id
        )
        flash(f"Access revoked for {target_user.full_name if target_user else 'user'}. Future downloads are now blocked.", 'info')
    else:
        flash("Permission record not found.", 'warning')

    return redirect(url_for('documents.manage_access', doc_id=doc_id))


@documents_bp.route('/<int:doc_id>/delete', methods=['POST'])
@login_required
def delete(doc_id):
    """
    Delete a document.
    Allowed ONLY for the document OWNER.
    Performs soft-delete metadata marking and safely deletes underlying physical file.
    """
    document = db.get_or_404(Document, doc_id)
    tenant_id = get_active_tenant_id()

    authorized, reason = can_access_document(document, current_user, action='DELETE')
    if not authorized:
        log_audit_event(
            action='ACCESS_DENIED',
            resource_type='DOCUMENT',
            resource_id=str(doc_id),
            status='DENIED',
            details=f"Delete rejected: {reason}",
            tenant_id=tenant_id,
            user_id=current_user.id
        )
        abort(403)

    storage_filename = document.storage_filename
    original_filename = document.original_filename

    # Delete physical file
    delete_stored_file(current_app.config['UPLOAD_FOLDER'], storage_filename)

    # Mark deleted in DB (cascade removes permissions)
    document.is_deleted = True
    db.session.commit()

    log_audit_event(
        action='DELETE_DOCUMENT',
        resource_type='DOCUMENT',
        resource_id=str(doc_id),
        status='SUCCESS',
        details=f"Deleted document '{original_filename}'",
        tenant_id=document.tenant_id,
        user_id=current_user.id
    )

    flash(f"Document '{original_filename}' has been deleted.", 'info')
    return redirect(url_for('documents.my_documents'))
