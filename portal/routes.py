from datetime import date, datetime, timezone
import json
import re
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for

from . import db
from .ise_client import ISEClient
from .models import AuditEvent, Cluster
from .security import decrypt_secret, encrypt_secret

bp = Blueprint("portal", __name__)


def audit(action, target, result, detail=None):
    db.session.add(AuditEvent(action=action, target=target, result=result, detail=detail))
    db.session.commit()


@bp.get("/")
def dashboard():
    clusters = Cluster.query.order_by(Cluster.name).all()
    events = AuditEvent.query.order_by(AuditEvent.created_at.desc()).limit(8).all()
    return render_template(
        "dashboard.html", clusters=clusters, events=events
    )


@bp.get("/clusters/<int:cluster_id>")
def cluster_details(cluster_id):
    cluster = db.get_or_404(Cluster, cluster_id)
    events = AuditEvent.query.filter_by(target=cluster.name).order_by(AuditEvent.created_at.desc()).limit(20).all()
    return render_template("cluster_details.html", cluster=cluster, events=events)


@bp.get("/clusters/<int:cluster_id>/certificates")
def cluster_certificates(cluster_id):
    cluster = db.get_or_404(Cluster, cluster_id)
    inventory = {"system_certificates": [], "trusted_certificates": [], "errors": []}
    if current_app.config["ISE_PORTAL_DEMO"] and not cluster.encrypted_password:
        for node in cluster.node_detail_list:
            for certificate in node.get("certificates", []):
                inventory["system_certificates"].append({
                    "hostname": node.get("hostname", "Unknown node"),
                    "friendly_name": certificate.get("friendly_name", "Unnamed certificate"),
                    "subject": "Demo certificate",
                    "issued_by": "Demo issuer",
                    "used_by": "Admin",
                    "expiration": certificate.get("expiration", "Unavailable"),
                    "status": "—",
                })
    else:
        try:
            inventory = ISEClient(
                cluster, decrypt_secret(cluster.encrypted_password)
            ).certificate_inventory()
            audit("certificate.inventory", cluster.name, "success", "Certificate inventory viewed")
        except Exception as exc:
            inventory["errors"].append(str(exc))
            audit("certificate.inventory", cluster.name, "failed", str(exc))
    return render_template("certificates.html", cluster=cluster, inventory=inventory)


@bp.route("/clusters/<int:cluster_id>/certificates/import", methods=["GET", "POST"])
def import_trusted_certificate(cluster_id):
    cluster = db.get_or_404(Cluster, cluster_id)
    if request.method == "POST":
        action_username = request.form.get("action_username", "").strip()
        action_password = request.form.get("action_password", "")
        if not action_username or not action_password:
            flash("Enter the username and password to use for this import.", "danger")
            return render_template("import_trusted_certificate.html", cluster=cluster), 400

        certificate_file = request.files.get("certificate")
        if not certificate_file or not certificate_file.filename:
            flash("Choose a PEM certificate file to import.", "danger")
            return render_template("import_trusted_certificate.html", cluster=cluster), 400

        certificate_bytes = certificate_file.read(1024 * 1024 + 1)
        if len(certificate_bytes) > 1024 * 1024:
            flash("The certificate file must be 1 MB or smaller.", "danger")
            return render_template("import_trusted_certificate.html", cluster=cluster), 400
        try:
            certificate_data = certificate_bytes.decode("utf-8-sig").strip()
        except UnicodeDecodeError:
            certificate_data = ""
        if not (
            "-----BEGIN CERTIFICATE-----" in certificate_data
            and "-----END CERTIFICATE-----" in certificate_data
        ):
            flash("The selected file is not a valid PEM certificate.", "danger")
            return render_template("import_trusted_certificate.html", cluster=cluster), 400

        admin_auth = request.form.get("trust_for_certificate_based_admin_auth") == "on"
        client_auth = request.form.get("trust_for_client_auth") == "on" or admin_auth
        ise_auth = request.form.get("trust_for_ise_auth") == "on" or client_auth
        try:
            if current_app.config["ISE_PORTAL_DEMO"] and not cluster.encrypted_password:
                result = {"response": {"message": "Demo import completed"}}
            else:
                result = ISEClient(
                    cluster, action_password, username=action_username
                ).import_trusted_certificate(
                    certificate_data,
                    name=request.form.get("name", "").strip(),
                    description=request.form.get("description", "").strip(),
                    trust_for_ise_auth=ise_auth,
                    trust_for_client_auth=client_auth,
                    trust_for_certificate_based_admin_auth=admin_auth,
                    trust_for_cisco_services_auth=(
                        request.form.get("trust_for_cisco_services_auth") == "on"
                    ),
                    validate_certificate_extensions=(
                        request.form.get("validate_certificate_extensions") == "on"
                    ),
                )
            message = ISEClient._find(result, "message") or "Trusted certificate imported."
            audit("certificate.import", cluster.name, "success", message)
            flash(message, "success")
            return redirect(url_for("portal.cluster_certificates", cluster_id=cluster.id))
        except Exception as exc:
            audit("certificate.import", cluster.name, "failed", str(exc))
            flash(f"Trusted certificate import failed: {exc}", "danger")
    return render_template("import_trusted_certificate.html", cluster=cluster)


@bp.route("/clusters/<int:cluster_id>/certificates/import-system", methods=["GET", "POST"])
def import_system_certificate(cluster_id):
    cluster = db.get_or_404(Cluster, cluster_id)
    if request.method == "POST":
        action_username = request.form.get("action_username", "").strip()
        action_password = request.form.get("action_password", "")
        private_key_password = request.form.get("private_key_password", "")
        if not action_username or not action_password:
            flash("Enter the username and password to use for this import.", "danger")
            return render_template("import_system_certificate.html", cluster=cluster), 400
        if not private_key_password:
            flash("Enter the private-key password.", "danger")
            return render_template("import_system_certificate.html", cluster=cluster), 400

        certificate_data = _read_pem_upload(
            request.files.get("certificate"), ("CERTIFICATE",), "certificate"
        )
        private_key_data = _read_pem_upload(
            request.files.get("private_key"),
            ("ENCRYPTED PRIVATE KEY", "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"),
            "private-key",
        )
        if isinstance(certificate_data, str) and certificate_data.startswith("ERROR:"):
            flash(certificate_data[6:], "danger")
            return render_template("import_system_certificate.html", cluster=cluster), 400
        if isinstance(private_key_data, str) and private_key_data.startswith("ERROR:"):
            flash(private_key_data[6:], "danger")
            return render_template("import_system_certificate.html", cluster=cluster), 400

        saml = request.form.get("saml") == "on"
        settings = {
            role: request.form.get(role) == "on"
            for role in ("admin", "eap", "ims", "portal", "pxgrid", "radius")
        }
        if saml:
            settings = {role: False for role in settings}
        settings["saml"] = saml
        try:
            if current_app.config["ISE_PORTAL_DEMO"] and not cluster.encrypted_password:
                result = {"response": {"message": "Demo system certificate import completed"}}
            else:
                result = ISEClient(
                    cluster, action_password, username=action_username
                ).import_system_certificate(
                    certificate_data,
                    private_key_data,
                    private_key_password,
                    name=request.form.get("name", "").strip(),
                    allow_extended_validity=request.form.get("allow_extended_validity") == "on",
                    allow_wildcard_certificates=request.form.get("allow_wildcard_certificates") == "on",
                    validate_certificate_extensions=request.form.get("validate_certificate_extensions") == "on",
                    **settings,
                )
            message = ISEClient._find(result, "message") or "System certificate imported."
            audit("certificate.system_import", cluster.name, "success", message)
            flash(message, "success")
            return redirect(url_for("portal.cluster_certificates", cluster_id=cluster.id))
        except Exception as exc:
            audit("certificate.system_import", cluster.name, "failed", str(exc))
            flash(f"System certificate import failed: {exc}", "danger")
    return render_template("import_system_certificate.html", cluster=cluster)


def _read_pem_upload(upload, pem_labels, display_name):
    if not upload or not upload.filename:
        return f"ERROR:Choose a PEM {display_name} file."
    content = upload.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        return f"ERROR:The {display_name} file must be 1 MB or smaller."
    try:
        text = content.decode("utf-8-sig").strip()
    except UnicodeDecodeError:
        return f"ERROR:The selected file is not a valid PEM {display_name}."
    if not any(
        f"-----BEGIN {label}-----" in text and f"-----END {label}-----" in text
        for label in pem_labels
    ):
        return f"ERROR:The selected file is not a valid PEM {display_name}."
    return text


@bp.route("/clusters/new", methods=["GET", "POST"])
def add_cluster():
    if request.method == "POST":
        try:
            cluster = Cluster(
                name=request.form["name"].strip(),
                base_url=request.form["pan01_base_url"].strip().rstrip("/"),
                pan02_base_url=request.form.get("pan02_base_url", "").strip().rstrip("/") or None,
                region="Unassigned",
                username=request.form["username"].strip(),
                encrypted_password=encrypt_secret(request.form["password"]),
                verify_tls=request.form.get("verify_tls") == "on",
                ca_bundle=request.form.get("ca_bundle", "").strip() or None,
            )
            db.session.add(cluster)
            db.session.commit()
            audit("cluster.add", cluster.name, "success")
            flash(f"{cluster.name} added.", "success")
            return redirect(url_for("portal.dashboard"))
        except Exception as exc:
            db.session.rollback()
            flash(str(exc), "danger")
    return render_template("cluster_form.html", cluster=None)


@bp.route("/clusters/<int:cluster_id>/edit", methods=["GET", "POST"])
def edit_cluster(cluster_id):
    cluster = db.get_or_404(Cluster, cluster_id)
    return_url = _edit_cluster_return_url(cluster)
    if request.method == "POST":
        try:
            cluster.name = request.form["name"].strip()
            cluster.pan01_base_url = request.form["pan01_base_url"].strip().rstrip("/")
            cluster.pan02_base_url = request.form.get("pan02_base_url", "").strip().rstrip("/") or None
            cluster.username = request.form["username"].strip()
            cluster.verify_tls = request.form.get("verify_tls") == "on"
            cluster.ca_bundle = request.form.get("ca_bundle", "").strip() or None
            new_password = request.form.get("password", "")
            if new_password:
                cluster.encrypted_password = encrypt_secret(new_password)
            db.session.commit()
            audit("cluster.update", cluster.name, "success", "Connection settings updated")
            flash(f"{cluster.name} settings updated.", "success")
            return redirect(return_url)
        except Exception as exc:
            db.session.rollback()
            flash(str(exc), "danger")
    return render_template("cluster_form.html", cluster=cluster, return_url=return_url)


def _edit_cluster_return_url(cluster):
    candidate = request.form.get("return_to") or request.args.get("next")
    allowed = {
        url_for("portal.dashboard"),
        url_for("portal.cluster_details", cluster_id=cluster.id),
    }
    return candidate if candidate in allowed else url_for(
        "portal.cluster_details", cluster_id=cluster.id
    )


@bp.post("/clusters/<int:cluster_id>/check")
def check_cluster(cluster_id):
    cluster = db.get_or_404(Cluster, cluster_id)
    wants_json = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    if current_app.config["ISE_PORTAL_DEMO"] and not cluster.encrypted_password:
        cluster.last_checked = datetime.now(timezone.utc)
        db.session.commit()
        audit("cluster.health", cluster.name, "success", "Demo health check")
        if wants_json:
            return jsonify(_cluster_card_data(cluster))
        flash(f"{cluster.name} is reachable (demo).", "success")
        return redirect(url_for("portal.dashboard"))
    try:
        result = ISEClient(cluster, decrypt_secret(cluster.encrypted_password)).health()
        node_statuses = result.get("node_statuses") or []
        cluster.status = "healthy" if _all_nodes_connected(node_statuses) else "warning"
        cluster.latency_ms = result["latency_ms"]
        if result.get("node_statuses") is not None:
            cluster.node_statuses = json.dumps(result["node_statuses"])
        if result.get("system_certificate_statuses") is not None:
            cluster.system_certificate_statuses = json.dumps(result["system_certificate_statuses"])
        if result.get("node_details") is not None:
            cluster.node_details = json.dumps(result["node_details"])
        for field in ("version", "latest_patch", "node_count", "primary_pan", "backup_status", "replication_status", "saml_cert_expirations"):
            if result.get(field) is not None:
                setattr(cluster, field, result[field])
        cluster.last_checked = datetime.now(timezone.utc)
        db.session.commit()
        audit("cluster.health", cluster.name, "success", f'{result["latency_ms"]} ms')
        missing = [
            label for field, label in (
                ("version", "version"), ("latest_patch", "patch"),
                ("primary_pan", "Primary PAN"),
                ("backup_status", "backup"), ("replication_status", "replication"),
            ) if not result.get(field)
        ]
        if wants_json:
            return jsonify(_cluster_card_data(cluster))
        if missing:
            flash(f"{cluster.name} is reachable. No usable value was returned for: {', '.join(missing)}.", "warning")
        else:
            flash(f"{cluster.name} details refreshed.", "success")
    except Exception as exc:
        cluster.status = "offline"
        cluster.last_checked = datetime.now(timezone.utc)
        db.session.commit()
        audit("cluster.health", cluster.name, "failed", str(exc))
        if wants_json:
            return jsonify(_cluster_card_data(cluster)), 503
    return redirect(url_for("portal.dashboard"))


def _cluster_card_data(cluster):
    return {
        "status": cluster.status,
        "version": cluster.version or "Unavailable",
        "latest_patch": cluster.latest_patch or "Unavailable",
        "node_count": cluster.node_count if cluster.node_count is not None else "Unavailable",
        "primary_pan": cluster.primary_pan or "Unavailable",
        "backup_status": cluster.backup_status or "Unavailable",
        "replication_status": cluster.replication_status or "Unavailable",
        "node_statuses": cluster.node_status_list,
        "saml_cert_expirations": _certificate_expiration_dates(cluster.saml_cert_expirations),
        "system_certificate_statuses": cluster.system_certificate_status_list,
    }


def _certificate_expiration_dates(value):
    if not value:
        return "Unavailable"
    dates = re.findall(r"\b\d{2}/\d{2}/\d{2}\b", value)
    return " · ".join(dates) if dates else value


def _system_certificate_health(value, today=None):
    if not value or value == "None found":
        return "unavailable"
    expiration_dates = re.findall(r"\b(\d{2})/(\d{2})/(\d{2})\b", value)
    if not expiration_dates:
        return "unavailable"
    today = today or date.today()
    expirations = [
        date(2000 + int(year), int(month), int(day))
        for month, day, year in expiration_dates
    ]
    return "expired" if any(expiration < today for expiration in expirations) else "healthy"


def _all_nodes_connected(node_statuses):
    return bool(node_statuses) and all(
        str(node.get("status", "")).strip().lower() == "connected"
        for node in node_statuses
    )


@bp.post("/clusters/<int:cluster_id>/delete")
def delete_cluster(cluster_id):
    cluster = db.get_or_404(Cluster, cluster_id)
    cluster_name = cluster.name
    db.session.delete(cluster)
    db.session.commit()
    audit("cluster.remove", cluster_name, "success")
    flash(f"{cluster_name} removed from the deployment inventory.", "success")
    return redirect(url_for("portal.dashboard"))


@bp.get("/audit")
def audit_log():
    events = AuditEvent.query.order_by(AuditEvent.created_at.desc()).limit(250).all()
    return render_template("audit.html", events=events)
