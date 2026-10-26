from datetime import datetime, timezone
import json
from . import db


class Cluster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    base_url = db.Column(db.String(255), nullable=False)
    pan02_base_url = db.Column(db.String(255), nullable=True)

    @property
    def pan01_base_url(self):
        """The original base_url column is PAN01 for backward compatibility."""
        return self.base_url

    @pan01_base_url.setter
    def pan01_base_url(self, value):
        self.base_url = value
    region = db.Column(db.String(80), nullable=False, default="Unassigned")
    username = db.Column(db.String(120), nullable=True)
    encrypted_password = db.Column(db.Text, nullable=True)
    verify_tls = db.Column(db.Boolean, nullable=False, default=True)
    ca_bundle = db.Column(db.String(255), nullable=True)
    version = db.Column(db.String(40), nullable=True)
    latest_patch = db.Column(db.String(80), nullable=True)
    licensing_status = db.Column(db.String(120), nullable=True)
    node_count = db.Column(db.Integer, nullable=True)
    primary_pan = db.Column(db.String(255), nullable=True)
    backup_status = db.Column(db.String(160), nullable=True)
    replication_status = db.Column(db.String(160), nullable=True)
    node_statuses = db.Column(db.Text, nullable=True)
    system_certificate_statuses = db.Column(db.Text, nullable=True)
    node_details = db.Column(db.Text, nullable=True)
    saml_cert_expirations = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="unknown")
    latency_ms = db.Column(db.Integer, nullable=True)
    last_checked = db.Column(db.DateTime(timezone=True), nullable=True)

    @property
    def node_status_list(self):
        try:
            value = json.loads(self.node_statuses or "[]")
            return value if isinstance(value, list) else []
        except (TypeError, ValueError):
            return []

    @property
    def system_certificate_status_list(self):
        try:
            value = json.loads(self.system_certificate_statuses or "[]")
            return value if isinstance(value, list) else []
        except (TypeError, ValueError):
            return []

    @property
    def node_detail_list(self):
        try:
            value = json.loads(self.node_details or "[]")
            return value if isinstance(value, list) else []
        except (TypeError, ValueError):
            return []


class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    actor = db.Column(db.String(120), nullable=False, default="local-admin")
    action = db.Column(db.String(80), nullable=False)
    target = db.Column(db.String(160), nullable=False)
    result = db.Column(db.String(20), nullable=False)
    detail = db.Column(db.Text, nullable=True)
