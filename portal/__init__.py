import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text

db = SQLAlchemy()


def _add_missing_cluster_columns():
    """Small SQLite-friendly migration for databases created by the MVP."""
    existing = {column["name"] for column in inspect(db.engine).get_columns("cluster")}
    additions = {
        "pan02_base_url": "VARCHAR(255)",
        "latest_patch": "VARCHAR(80)",
        "licensing_status": "VARCHAR(120)",
        "node_count": "INTEGER",
        "primary_pan": "VARCHAR(255)",
        "backup_status": "VARCHAR(160)",
        "replication_status": "VARCHAR(160)",
        "node_statuses": "TEXT",
        "system_certificate_statuses": "TEXT",
        "node_details": "TEXT",
        "saml_cert_expirations": "TEXT",
    }
    with db.engine.begin() as connection:
        for name, sql_type in additions.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE cluster ADD COLUMN {name} {sql_type}"))


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "dev-only-change-me"),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///ise_portal.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        ISE_PORTAL_MASTER_KEY=os.getenv("ISE_PORTAL_MASTER_KEY", ""),
        ISE_PORTAL_DEMO=os.getenv("ISE_PORTAL_DEMO", "0") == "1",
    )
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    from .routes import bp
    app.register_blueprint(bp)

    with app.app_context():
        db.create_all()
        _add_missing_cluster_columns()
        if app.config["ISE_PORTAL_DEMO"]:
            from .models import Cluster
            if not Cluster.query.first():
                db.session.add_all([
                    Cluster(name="New York", base_url="https://ise-nyc.example.net", region="Americas", version="3.3", latest_patch="Patch 4", licensing_status="Authorized", node_count=6, primary_pan="ise-nyc-pan01", backup_status="Succeeded · 8h ago", replication_status="In sync", node_statuses='[{"name":"ise-nyc-pan01","status":"Connected"}]', saml_cert_expirations="03/23/29 · 03/28/29", status="healthy", latency_ms=82),
                    Cluster(name="London", base_url="https://ise-lon.example.net", region="EMEA", version="3.3", latest_patch="Patch 4", licensing_status="Authorized", node_count=4, primary_pan="ise-lon-pan01", backup_status="Succeeded · 19h ago", replication_status="1 node out of sync", node_statuses='[{"name":"ise-lon-pan01","status":"Connected"},{"name":"ise-lon-psn01","status":"NotInSync"}]', saml_cert_expirations="04/12/29 · 04/12/29", status="warning", latency_ms=147),
                    Cluster(name="Singapore", base_url="https://ise-sin.example.net", region="APAC", version="3.2", latest_patch="Patch 7", licensing_status="Authorized", node_count=4, primary_pan="ise-sin-pan01", backup_status="Succeeded · 11h ago", replication_status="In sync", node_statuses='[{"name":"ise-sin-pan01","status":"Connected"}]', saml_cert_expirations="09/08/28 · 09/08/28", status="healthy", latency_ms=221),
                ])
                db.session.commit()
    return app
