# TrustVault — Threat Model & Security Analysis (THREATS.md)

**Project:** TrustVault — Secure Sharing, Smarter Access, Verifiable Accountability  
**Challenge:** Snovasys Fresher Hiring Challenge 2026  
**Methodology:** STRIDE Threat Classification & Defense-in-Depth Analysis

---

## 1. System Assets & Security Objectives

| Asset | Sensitivity | Security Objective |
|---|---|---|
| **Document Files on Disk** | High | Confidentiality & Integrity. Prevent unauthorized reading, path traversal, overwriting, or direct web URL exposure. |
| **Document Metadata** | Medium | Confidentiality & Isolation. Ensure tenant A cannot see filenames, categories, or descriptions from tenant B. |
| **User Passwords** | Critical | Confidentiality. Passwords must never exist in plaintext; stored using PBKDF2:SHA256/scrypt with per-user salt. |
| **User Sessions** | High | Integrity & Confidentiality. Guard against hijacking, fixation, cross-site leaks (`HttpOnly`, `SameSite=Lax`, `Secure`). |
| **Access Permissions** | High | Integrity. Only document owners can grant or revoke access; immediate revocation enforcement. |
| **Audit Log Trail** | High | Accountability & Non-repudiation. Log all security operations with actor, timestamp, tenant, resource, and outcome. |

---

## 2. Trust Boundaries & Attack Surfaces

```mermaid
flowchart TD
    subgraph Untrusted External Zone
        Attacker[Attacker / Malicious Client]
        AuthorizedUser[Legitimate User Browser]
    end

    subgraph Trust Boundary 1: Transport & Network
        LB[Reverse Proxy / TLS Termination]
    end

    subgraph Trust Boundary 2: Application Layer (Flask)
        AuthzEngine[Authorization & Session Middleware]
        UploadValidator[File Type & Size Sanitizer]
        AuditService[Audit Logger]
    end

    subgraph Trust Boundary 3: Storage Layer
        DB[(SQLite Database)]
        PrivateDisk[(Private Disk Storage: instance/uploads/)]
    end

    Attacker -->|Forged requests, Path Traversal, CSRF| LB
    AuthorizedUser -->|HTTPS + Session Cookie| LB
    LB --> AuthzEngine
    AuthzEngine --> UploadValidator
    UploadValidator --> PrivateDisk
    AuthzEngine --> DB
    AuthzEngine --> AuditService
    AuditService --> DB
```

---

## 3. STRIDE Threat Analysis & Implemented Mitigations

### 3.1 Spoofing (Identity Deception)
* **Threat:** An attacker guesses a user password or reuses a stolen session cookie.
* **Mitigation:**
  - Werkzeug `generate_password_hash` with `check_password_hash`. Minimum 8 characters enforced.
  - Session cookies marked `HttpOnly` (inaccessible to JavaScript) and `SameSite=Lax` (immune to cross-site credential leakage).
  - Explicit session invalidation on `/auth/logout`.
* **Linked Automated Tests:**
  - `tests/test_auth.py::test_password_hashing`
  - `tests/test_auth.py::test_login_success_and_logout`
  - `tests/test_auth.py::test_login_invalid_password`
  - `tests/test_auth.py::test_anonymous_user_redirected_to_login`

### 3.2 Tampering (Data Modification & Integrity Attacks)
* **Threat 1:** Cross-Site Request Forgery (CSRF) where a malicious site forces an authenticated user to delete a document or grant access.
  - **Mitigation:** Flask-WTF CSRF tokens required on all POST forms and mutation endpoints.
* **Threat 2:** Attacker uploads a file named `../../../../etc/passwd` to overwrite server files.
  - **Mitigation:** `sanitize_filename()` via Werkzeug `secure_filename()` strips directory traversal characters; files are saved on disk using randomly generated UUIDs (`uuid.uuid4().hex + ext`), never user-provided filenames.
* **Threat 3:** Cross-Site Scripting (XSS) via document descriptions or filenames.
  - **Mitigation:** Jinja2 template autoescaping enabled; characters like `'`, `"`, `<`, `>` are automatically converted to HTML entities (e.g., `&#39;`).
* **Linked Automated Tests:**
  - `tests/test_documents.py::test_path_traversal_prevention_in_filename`
  - `tests/test_documents.py::test_random_uuid_storage_name_and_private_location`
  - `tests/test_documents.py::test_document_deletion_removes_physical_file`

### 3.3 Repudiation (Denial of Actions)
* **Threat:** A user claims they never downloaded, deleted, or shared a confidential document.
* **Mitigation:**
  - Centralized `AuditEvent` service records actor ID, organization/tenant ID, action (`UPLOAD_DOCUMENT`, `DOWNLOAD_DOCUMENT`, `DELETE_DOCUMENT`, `GRANT_PERMISSION`, `REVOKE_PERMISSION`, `ACCESS_DENIED`, `LOGIN_SUCCESS`, `LOGIN_FAILURE`), resource ID, client IP address, timestamp, and outcome (`SUCCESS`, `FAILURE`, `DENIED`).
  - Read-only audit viewer accessible strictly to organization administrators (`/admin/audit-logs`).
* **Linked Automated Tests:**
  - `tests/test_audit.py::test_audit_logs_login_events`
  - `tests/test_audit.py::test_audit_logs_document_operations`
  - `tests/test_audit.py::test_audit_logs_access_denied_events`

### 3.4 Information Disclosure (Unauthorized Data Access)
* **Threat 1: Cross-Tenant Data Access (Horizontal Privilege Escalation).**
  - An attacker from Company B attempts to access Company A documents by guessing numeric document IDs (`/documents/1/download`).
  - **Mitigation:** Every document query and download endpoint checks `can_access_document()`. The document's `tenant_id` must match `user.is_tenant_member()`. Non-members receive immediate HTTP 403 Forbidden.
* **Threat 2: Direct Static File URL Snooping.**
  - An attacker tries to fetch files directly via `/static/uploads/file.pdf`.
  - **Mitigation:** Uploads are placed strictly in `instance/uploads/` (outside Flask's `static` directory). Files can only be downloaded through `/documents/<id>/download` using `send_from_directory` after session authentication and RBAC verification.
* **Threat 3: Cross-Tenant Sharing Leakage.**
  - An owner attempts to share a file with an external email.
  - **Mitigation:** `manage_access` validates that recipient exists AND is an active member of the same tenant.
* **Linked Automated Tests:**
  - `tests/test_tenancy.py::test_cross_tenant_download_prohibited`
  - `tests/test_tenancy.py::test_cross_tenant_delete_prohibited`
  - `tests/test_tenancy.py::test_cross_tenant_sharing_prevented`
  - `tests/test_tenancy.py::test_document_listing_strictly_scoped_to_active_tenant`

### 3.5 Denial of Service (Resource Exhaustion)
* **Threat:** An attacker uploads massive gigabyte files or floods disk storage with malicious scripts.
* **Mitigation:**
  - `MAX_CONTENT_LENGTH = 10 * 1024 * 1024` (10 MB strict limit).
  - Strict extension allowlist: `pdf, docx, txt, png, jpg, jpeg, csv, xlsx`. Executable binaries (`.exe`, `.sh`, `.py`, `.php`) are rejected immediately.
* **Linked Automated Tests:**
  - `tests/test_documents.py::test_disallowed_file_types_rejected`
  - `tests/test_documents.py::test_allowed_file_types_accepted`

### 3.6 Elevation of Privilege (Vertical Privilege Escalation)
* **Threat 1: Public Admin Registration.**
  - A user registers as an `ADMIN` to view all audit logs and tenant users.
  - **Mitigation:** Public registration route (`/auth/register`) strictly assigns the `OWNER` role for the new tenant. The `ADMIN` role cannot be self-selected; it is provisioned only through the controlled CLI command `flask bootstrap-admin` using environment secrets.
* **Threat 2: VIEWER uploading or deleting files.**
  - A user assigned `VIEWER` attempts to upload, delete, or share documents.
  - **Mitigation:** `@require_role('OWNER')` and `can_access_document()` enforced on all mutating routes.
* **Linked Automated Tests:**
  - `tests/test_permissions.py::test_viewer_cannot_upload_document`
  - `tests/test_permissions.py::test_viewer_cannot_access_unshared_document`
  - `tests/test_permissions.py::test_viewer_cannot_delete_or_manage_sharing`
  - `tests/test_admin.py::test_admin_routes_restricted_to_admin_role`
  - `tests/test_admin.py::test_cli_bootstrap_admin`

---

## 4. Residual Risks & Technical Limitations

1. **Database Log Tamper-Proofing:**
   - *Residual Risk:* While application routes enforce append-only audit logging, database logs are not inherently cryptographic or immutable against an attacker who gains direct SSH root or database administrator access to the host server.
   - *Enterprise Mitigation:* In production, stream audit events to an external immutable WORM (Write Once Read Many) log service (e.g. AWS CloudWatch, Google Cloud Logging, or Datadog).

2. **Revocation vs. Local Client Copies:**
   - *Residual Risk:* Revoking document permission immediately cuts off all future application downloads and queries. However, it cannot remotely erase or recall copies that the recipient already downloaded to their personal local hard drive.
   - *Design Notice:* This technical limitation is explicitly documented on the UI manage access page and in user documentation.

3. **Antivirus / Malware Sandboxing:**
   - *Residual Risk:* The application validates file extensions, enforces strict MIME types, sanitizes names, and isolates files outside static roots. However, it does not execute deep heuristic malware inspection or sandbox detonation.
   - *Candidate Truthfulness:* We do NOT claim malware scanning because an external scanning daemon (like ClamAV) is not installed in this environment.
