from portal import create_app, db
from portal.ise_client import ISEClient
from portal.models import Cluster
from datetime import date
from io import BytesIO
import requests

from portal.routes import _all_nodes_connected, _certificate_expiration_dates, _system_certificate_health


def make_app():
    return create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite://", "ISE_PORTAL_DEMO": True})


def test_dashboard_loads():
    client = make_app().test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"Every ISE deployment" in response.data
    assert b"Monitor geographically distributed clusters" not in response.data
    assert b">Clusters</span>" in response.data
    assert b">Clusters Requiring Attention</span>" in response.data
    assert b"Latest patch" in response.data
    assert b"Status of Nodes" in response.data
    assert b"Last successful backup" in response.data
    assert b"System Cert Status" in response.data
    assert b"API Gateway / HTTPS 443" not in response.data
    assert b'class="button" href="/clusters/new">Add Cluster</a>' in response.data
    assert response.data.count(b">Add Cluster</a>") == 1
    assert b"data-attention-filter" in response.data
    assert b"applyAttentionFilter" in response.data


def test_title_bar_is_sticky():
    response = make_app().test_client().get("/static/ise-theme.css")
    assert response.status_code == 200
    assert b"header{position:sticky;top:0;z-index:1000" in response.data


def test_offline_cluster_card_is_grayed_and_uses_dash_indicators():
    app = make_app()
    with app.app_context():
        cluster = db.session.get(Cluster, 1)
        cluster.status = "offline"
        db.session.commit()
    response = app.test_client().get("/")
    assert response.status_code == 200
    assert b'class="cluster offline"' in response.data
    assert b"renderOfflineIndicator" in response.data

    details = app.test_client().get("/clusters/1")
    assert details.status_code == 200
    assert b'class="detail-panel offline"' in details.data
    assert b"operationalOffline" in details.data
    assert b"Certificate management is unavailable while the cluster is offline" in details.data


def test_cluster_form_loads():
    response = make_app().test_client().get("/clusters/new")
    assert response.status_code == 200
    assert b"Add an ISE cluster" in response.data
    assert b"Region" not in response.data
    assert b'name="pan01_base_url" type="url" required' in response.data
    assert b'name="pan02_base_url" type="url"' in response.data
    assert b'PAN02 Base URL <small>(optional)</small>' in response.data
    assert b'name="base_url"' not in response.data


def test_all_child_pages_include_previous_and_home_navigation():
    client = make_app().test_client()
    for path in (
        "/clusters/new",
        "/clusters/1",
        "/clusters/1/edit",
        "/clusters/1/certificates",
        "/clusters/1/certificates/import",
        "/clusters/1/certificates/import-system",
        "/audit",
    ):
        response = client.get(path)
        assert response.status_code == 200
        assert b"Previous Page" in response.data
        assert b">Home</a>" in response.data


def test_cluster_details_page_loads():
    response = make_app().test_client().get("/clusters/1")
    assert response.status_code == 200
    assert b"CLUSTER DETAILS" in response.data
    assert b"Connection" in response.data
    assert b"Manage Certificates" in response.data
    assert "← Overview".encode("utf-8") not in response.data
    assert b"editSettingsUrl" in response.data


def test_certificate_management_page_loads():
    response = make_app().test_client().get("/clusters/1/certificates")
    assert response.status_code == 200
    assert b"Certificate Management" in response.data
    assert b"CERTIFICATE DETAILS" in response.data
    assert b"System Certificates" in response.data
    assert b"Trusted Certificates" in response.data
    assert b"Import Trusted Cert" in response.data


def test_import_trusted_certificate_form_loads():
    response = make_app().test_client().get("/clusters/1/certificates/import")
    assert response.status_code == 200
    assert b"Import Trusted Certificate" in response.data
    assert b"Certificate-based admin authentication" in response.data


def test_import_system_certificate_form_loads():
    response = make_app().test_client().get("/clusters/1/certificates/import-system")
    assert response.status_code == 200
    assert b"Import System Certificate" in response.data
    assert b"Private-key file" in response.data
    assert b"Assigning the Admin Portal role causes ISE services to restart" in response.data


def test_demo_system_certificate_import_accepts_certificate_and_key():
    response = make_app().test_client().post(
        "/clusters/1/certificates/import-system",
        data={
            "action_username": "certificate-admin",
            "action_password": "temporary-password",
            "private_key_password": "private-key-password",
            "certificate": (
                BytesIO(b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"),
                "system.pem",
            ),
            "private_key": (
                BytesIO(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nTEST\n-----END ENCRYPTED PRIVATE KEY-----\n"),
                "system.key",
            ),
            "admin": "on",
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Demo system certificate import completed" in response.data


def test_demo_trusted_certificate_import_accepts_pem():
    response = make_app().test_client().post(
        "/clusters/1/certificates/import",
        data={
            "name": "LTMA Root CA",
            "action_username": "certificate-admin",
            "action_password": "temporary-password",
            "certificate": (
                BytesIO(b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"),
                "ltma.pem",
            ),
            "trust_for_certificate_based_admin_auth": "on",
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Demo import completed" in response.data


def test_trusted_certificate_import_rejects_non_pem_file():
    response = make_app().test_client().post(
        "/clusters/1/certificates/import",
        data={
            "action_username": "certificate-admin",
            "action_password": "temporary-password",
            "certificate": (BytesIO(b"not a certificate"), "invalid.txt"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert b"not a valid PEM certificate" in response.data


def test_trusted_certificate_import_requires_action_credentials():
    response = make_app().test_client().post(
        "/clusters/1/certificates/import",
        data={
            "certificate": (
                BytesIO(b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"),
                "ltma.pem",
            ),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert b"Enter the username and password" in response.data


def test_ise_client_can_use_action_specific_username():
    class ClusterStub:
        username = "saved-user"

    client = ISEClient(ClusterStub(), "action-password", username="action-user")
    assert client.session.auth == ("action-user", "action-password")


def test_trusted_certificate_import_omits_blank_optional_fields():
    class Response:
        ok = True

        @staticmethod
        def json():
            return {"response": {"message": "Imported"}}

    client = object.__new__(ISEClient)
    captured = {}

    def request(method, path, **kwargs):
        captured.update({"method": method, "path": path, **kwargs})
        return Response()

    client.request = request
    client.import_trusted_certificate(
        "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
        name="",
        description="",
        trust_for_ise_auth=True,
    )

    assert "name" not in captured["json"]
    assert "description" not in captured["json"]
    assert captured["json"]["trustForIseAuth"] is True


def test_trusted_certificate_import_reports_ise_validation_message():
    class Response:
        ok = False
        status_code = 400
        text = ""

        @staticmethod
        def json():
            return {"response": {"message": "Certificate is not a CA certificate"}}

    client = object.__new__(ISEClient)
    client.request = lambda *args, **kwargs: Response()

    try:
        client.import_trusted_certificate("PEM")
        assert False, "Expected the import to fail"
    except RuntimeError as exc:
        assert str(exc) == (
            "ISE returned HTTP 400: Certificate is not a CA certificate"
        )


def test_system_certificate_import_uses_ise_33_transfer_field_names():
    class Response:
        ok = True

        @staticmethod
        def json():
            return {"response": {"message": "Imported"}}

    client = object.__new__(ISEClient)
    captured = {}

    def request(method, path, **kwargs):
        captured.update(kwargs)
        return Response()

    client.request = request
    client.import_system_certificate("CERT", "KEY", "password")

    payload = captured["json"]
    assert payload["allowRoleTransferForSameSubject"] is True
    assert payload["allowPortalTagTransferForSameSubject"] is True
    assert payload["portalGroupTag"] == "Default Portal Certificate Group"
    assert "roleTransferForSameSubject" not in payload
    assert "portalTagTransferForSameSubject" not in payload


def test_certificate_inventory_item_normalizes_api_fields():
    item = ISEClient._certificate_inventory_item({
        "friendlyName": "Admin Portal",
        "issuedTo": "CN=ise-pan01",
        "issuedBy": "CN=Internal CA",
        "usedBy": ["Admin", "EAP Authentication"],
        "expirationDate": "2029-03-28T01:14:22Z",
        "status": "VALID",
    }, hostname="ise-pan01")
    assert item == {
        "hostname": "ise-pan01",
        "friendly_name": "Admin Portal",
        "subject": "CN=ise-pan01",
        "issued_by": "CN=Internal CA",
        "used_by": "Admin, EAP Authentication",
        "expiration": "03/28/29",
        "status": "VALID",
    }


def test_system_certificate_inventory_status_is_based_on_expiration():
    active = ISEClient._certificate_inventory_item(
        {"expirationDate": "2099-03-28T01:14:22Z", "status": "Enabled"},
        status_from_expiration=True,
    )
    expired = ISEClient._certificate_inventory_item(
        {"expirationDate": "2020-03-28T01:14:22Z", "status": "Enabled"},
        status_from_expiration=True,
    )
    assert active["status"] == "Active"
    assert expired["status"] == "Expired"


def test_certificate_management_filter_requires_ltma_issuer_and_admin_usage():
    assert ISEClient._matches_certificate_filter({
        "issuedBy": "CN=ISE LTMA Certificate",
        "usedBy": ["Admin", "EAP Authentication"],
    })
    assert not ISEClient._matches_certificate_filter({
        "issuedBy": "CN=ISE SAML Certificate",
        "usedBy": "Admin",
    })
    assert not ISEClient._matches_certificate_filter({
        "issuedBy": "CN=ISE LTMA Certificate",
        "usedBy": "SAML",
    })
    assert not ISEClient._matches_certificate_filter({
        "issuedBy": "CN=ISE LTMA Certificate",
        "usedBy": None,
    })


def test_trusted_certificate_filter_uses_trusted_for_instead_of_used_by():
    certificate = {
        "issuedBy": "CN=ISE LTMA Certificate",
        "usedBy": None,
        "trustedFor": ["Admin", "Infrastructure"],
    }
    assert ISEClient._matches_certificate_filter(certificate, usage_field="trustedFor")
    assert not ISEClient._matches_certificate_filter(certificate)

    item = ISEClient._certificate_inventory_item(
        certificate, usage_field="trustedFor"
    )
    assert item["used_by"] == "Admin, Infrastructure"


def test_cluster_refresh_returns_card_json_for_ajax():
    client = make_app().test_client()
    response = client.post("/clusters/1/check", headers={"X-Requested-With": "XMLHttpRequest"})
    assert response.status_code == 200
    assert response.get_json()["status"] == "healthy"
    assert response.get_json()["node_statuses"][0] == {
        "name": "ise-nyc-pan01",
        "status": "Connected",
    }


def test_cluster_can_be_removed():
    client = make_app().test_client()
    response = client.post("/clusters/1/delete", follow_redirects=True)
    assert response.status_code == 200
    assert b"removed from the deployment inventory" in response.data
    assert b"cluster.remove" in response.data


def test_cluster_settings_can_be_edited_without_replacing_password():
    app = make_app()
    client = app.test_client()
    response = client.post("/clusters/1/edit", data={
        "name": "New York Updated",
        "region": "Americas",
        "pan01_base_url": "https://ise-new.example.net/",
        "pan02_base_url": "https://ise-new-pan02.example.net/",
        "username": "new-api-user",
        "password": "",
        "verify_tls": "on",
        "ca_bundle": "",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert response.request.path == "/clusters/1"
    assert b"New York Updated settings updated" in response.data
    assert b"CLUSTER DETAILS" in response.data
    assert b"cluster.update" in response.data
    with app.app_context():
        cluster = db.session.get(Cluster, 1)
        assert cluster.pan01_base_url == "https://ise-new.example.net"
        assert cluster.pan02_base_url == "https://ise-new-pan02.example.net"


def test_ise_client_falls_back_to_pan02_after_pan01_connection_error():
    class ClusterStub:
        pan01_base_url = "https://ise-pan01.example.net"
        pan02_base_url = "https://ise-pan02.example.net"
        username = "api-user"
        ca_bundle = None
        verify_tls = True
        primary_pan = None

    client = ISEClient(ClusterStub(), "password")
    requested_urls = []
    successful_response = object()

    def request(method, url, **kwargs):
        requested_urls.append(url)
        if "pan01" in url:
            raise requests.ConnectionError("PAN01 is unavailable")
        return successful_response

    client.session.request = request
    response = client.request("GET", "/api/v1/deployment/node")

    assert response is successful_response
    assert requested_urls == [
        "https://ise-pan01.example.net/api/v1/deployment/node",
        "https://ise-pan02.example.net/api/v1/deployment/node",
    ]


def test_ise_client_tries_last_known_primary_pan_first():
    class ClusterStub:
        pan01_base_url = "https://ise-pan01.example.net"
        pan02_base_url = "https://ise-pan02.example.net"
        primary_pan = "ise-pan02"
        username = "api-user"
        ca_bundle = None
        verify_tls = True

    client = ISEClient(ClusterStub(), "password")
    requested_urls = []
    client.session.request = lambda method, url, **kwargs: requested_urls.append(url) or object()

    client.request("GET", "/api/v1/deployment/node")

    assert requested_urls == ["https://ise-pan02.example.net/api/v1/deployment/node"]


def test_ise_client_defaults_new_cluster_to_pan01():
    class ClusterStub:
        pan01_base_url = "https://192.0.2.1"
        pan02_base_url = "https://192.0.2.2"
        primary_pan = None
        username = "api-user"
        ca_bundle = None
        verify_tls = True

    client = ISEClient(ClusterStub(), "password")
    requested_urls = []
    client.session.request = lambda method, url, **kwargs: requested_urls.append(url) or object()

    client.request("GET", "/api/v1/deployment/node")

    assert requested_urls == ["https://192.0.2.1/api/v1/deployment/node"]


def test_system_certificates_fall_back_when_primary_pan_endpoint_is_unavailable():
    class ClusterStub:
        pan01_base_url = "https://ise-pan01.example.net"
        pan02_base_url = "https://ise-pan02.example.net"
        primary_pan = "ise-pan02"
        username = "api-user"
        ca_bundle = None
        verify_tls = True

    class Response:
        def __init__(self, status_code, payload=None):
            self.status_code = status_code
            self.ok = 200 <= status_code < 400
            self._payload = payload

        def json(self):
            return self._payload

    client = ISEClient(ClusterStub(), "password")
    requested_urls = []

    def request(method, url, **kwargs):
        requested_urls.append(url)
        if url.startswith("https://ise-pan02.example.net/"):
            return Response(404, {})
        return Response(200, {"response": [{
            "friendlyName": "ISE-LTMA",
            "issuedBy": "CN=LTMA Root",
            "usedBy": "Admin",
            "expirationDate": "2030-01-01",
        }]})

    client.session.request = request
    result = client._system_certificate_data([{"hostname": "ise-pan02"}])

    assert result["node_statuses"] == [{"name": "ise-pan02", "status": "green"}]
    assert requested_urls == [
        "https://ise-pan02.example.net/api/v1/certs/system-certificate/ise-pan02",
        "https://ise-pan01.example.net/api/v1/certs/system-certificate/ise-pan02",
    ]


def test_edit_cluster_cancel_returns_to_cluster_details():
    response = make_app().test_client().get("/clusters/1/edit")
    assert response.status_code == 200
    assert b'href="/clusters/1">Cancel</a>' in response.data


def test_edit_opened_from_inventory_returns_to_inventory():
    app = make_app()
    client = app.test_client()
    edit_page = client.get("/clusters/1/edit?next=/")
    assert edit_page.status_code == 200
    assert b'name="return_to" value="/"' in edit_page.data
    assert b'href="/">Cancel</a>' in edit_page.data

    response = client.post("/clusters/1/edit", data={
        "name": "New York Updated",
        "pan01_base_url": "https://ise-new.example.net/",
        "pan02_base_url": "",
        "username": "new-api-user",
        "password": "",
        "verify_tls": "on",
        "ca_bundle": "",
        "return_to": "/",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert response.request.path == "/"
    assert b"CLUSTER INVENTORY" in response.data


def test_edit_rejects_external_return_target():
    response = make_app().test_client().get(
        "/clusters/1/edit?next=https://example.invalid/phishing"
    )
    assert response.status_code == 200
    assert b'name="return_to" value="/clusters/1"' in response.data


def test_ise_33_deployment_and_patch_payloads_are_parsed():
    nodes = [{"hostname": "ise-pan01", "roles": ["PrimaryAdmin"], "nodeStatus": "Connected"}]
    patches = [{"patchNumber": 2}, {"patchNumber": 4}]
    assert ISEClient._primary_pan(nodes) == "ise-pan01"
    assert ISEClient._latest_patch(patches) == "Patch 4"
    assert ISEClient._replication(nodes) == "In sync"
    assert ISEClient._node_statuses(nodes) == [{"name": "ise-pan01", "status": "Connected"}]


def test_health_does_not_request_licensing_data():
    class Response:
        ok = True

        @staticmethod
        def json():
            return {"response": []}

        @staticmethod
        def raise_for_status():
            return None

    client = object.__new__(ISEClient)
    requested_paths = []

    def request(method, path, **kwargs):
        requested_paths.append(path)
        return Response()

    client.request = request
    client.health()

    assert "/api/v1/license/system/tier-state" not in requested_paths


def test_node_statuses_preserve_each_nodes_reported_status():
    nodes = [
        {"hostname": "ise-pan01", "nodeStatus": "Connected"},
        {"hostname": "ise-psn01", "nodeStatus": "NotInSync"},
    ]

    assert ISEClient._node_statuses(nodes) == [
        {"name": "ise-pan01", "status": "Connected"},
        {"name": "ise-psn01", "status": "NotInSync"},
    ]


def test_cluster_is_healthy_only_when_every_node_is_connected():
    assert _all_nodes_connected([
        {"name": "ise-pan01", "status": "Connected"},
        {"name": "ise-psn01", "status": "connected"},
    ])
    assert not _all_nodes_connected([
        {"name": "ise-pan01", "status": "Connected"},
        {"name": "ise-psn01", "status": "NotInSync"},
    ])
    assert not _all_nodes_connected([])


def test_ise_33_replication_problems_are_summarized():
    nodes = [
        {"hostname": "ise-pan01", "nodeStatus": "Connected"},
        {"hostname": "ise-psn01", "nodeStatus": "NotInSync"},
        {"hostname": "ise-psn02", "nodeStatus": "ReplicationStopped"},
    ]
    status = ISEClient._replication(nodes)
    assert "Replication stopped (1)" in status
    assert "Not in sync (1)" in status


def test_null_backup_response_means_no_backup_history():
    class NullResponse:
        ok = True

        @staticmethod
        def json():
            return None

    client = object.__new__(ISEClient)
    client.request = lambda *args, **kwargs: NullResponse()
    assert client._backup_status("/unused") == "No history of backups"


def test_null_just_complete_means_no_backup_history():
    payload = {"response": {"justComplete": None}, "version": "1.0.0"}
    assert ISEClient._backup_summary(payload) == "No history of backups"


def test_completed_backup_with_failure_message_is_failed():
    payload = {"response": {
        "status": "COMPLETED",
        "error": "false",
        "message": "Backup failed: copy to repository failed",
        "justComplete": "yes",
        "startDate": "Mon Aug 10 06:37:34 EST 2026",
    }}
    assert ISEClient._backup_summary(payload) == "Failed · Copy to repository failed"


def test_completed_backup_without_failure_is_successful():
    payload = {"response": {
        "status": "COMPLETED",
        "error": "false",
        "message": "Backup completed",
        "justComplete": "yes",
        "startDate": "Mon Aug 10 06:37:34 EST 2026",
    }}
    assert ISEClient._backup_summary(payload) == "Successful · Mon Aug 10 06:37:34 EST 2026"


def test_ise_certificate_dates_are_formatted_for_cards():
    assert ISEClient._format_ise_date("Wed Mar 28 01:14:22 CST 2029") == "03/28/29"
    assert ISEClient._format_ise_date("2029-03-28T01:14:22Z") == "03/28/29"


def test_system_certificates_include_node_friendly_name_and_expiration():
    class CertificateResponse:
        ok = True

        @staticmethod
        def json():
            return {"response": [
                {
                    "issuedBy": "CN=ISE LTMA Certificate",
                    "usedBy": "Admin",
                    "friendlyName": "LTMA Portal Certificate",
                    "expirationDate": "Wed Mar 28 01:14:22 CST 2029",
                },
                {
                    "issuedBy": "CN=ISE SAML Certificate",
                    "usedBy": "SAML",
                    "friendlyName": "SAML Portal Certificate",
                    "expirationDate": "2029-04-12T01:14:22Z",
                },
                {
                    "issuedBy": "CN=ISE LTMA Certificate",
                    "usedBy": "SAML",
                    "friendlyName": "Non-Admin LTMA Certificate",
                    "expirationDate": "2029-04-12T01:14:22Z",
                },
            ]}

    client = object.__new__(ISEClient)
    client.request = lambda *args, **kwargs: CertificateResponse()

    result = client._saml_expirations([{"hostname": "ise-pan01.example.net"}])

    assert result == "ise-pan01.example.net\n• LTMA Portal Certificate — 03/28/29"


def test_inventory_certificate_summary_contains_only_expiration_dates():
    details = (
        "ise-pan01.example.net\n• SAML Portal Certificate — 03/28/29\n"
        "ise-psn01.example.net\n• SAML Signing Certificate — 04/12/29"
    )

    assert _certificate_expiration_dates(details) == "03/28/29 · 04/12/29"


def test_inventory_certificate_health_is_red_when_any_certificate_is_expired():
    today = date(2026, 8, 22)
    assert _system_certificate_health("08/21/26 · 04/12/29", today) == "expired"
    assert _system_certificate_health("08/22/26 · 04/12/29", today) == "healthy"
    assert _system_certificate_health("None found", today) == "unavailable"


def test_certificate_status_contains_one_result_per_node():
    class CertificateResponse:
        ok = True

        @staticmethod
        def json():
            return {"response": [{
                "issuedBy": "CN=ISE LTMA Certificate",
                "usedBy": "Admin",
                "friendlyName": "LTMA Admin Certificate",
                "expirationDate": "2029-04-12T01:14:22Z",
            }]}

    client = object.__new__(ISEClient)
    client.request = lambda *args, **kwargs: CertificateResponse()
    result = client._system_certificate_data([
        {"hostname": "ise-pan01.example.net"},
        {"hostname": "ise-psn01.example.net"},
    ])

    assert result["node_statuses"] == [
        {"name": "ise-pan01.example.net", "status": "green"},
        {"name": "ise-psn01.example.net", "status": "green"},
    ]


def test_certificate_status_preserves_results_when_one_node_is_unreachable():
    class CertificateResponse:
        ok = True

        @staticmethod
        def json():
            return {"response": [{
                "issuedBy": "CN=ISE LTMA Certificate",
                "usedBy": "Admin",
                "friendlyName": "LTMA Admin Certificate",
                "expirationDate": "2029-04-12T01:14:22Z",
            }]}

    client = object.__new__(ISEClient)

    def request(method, path, **kwargs):
        if path.endswith("ise-pan01.example.net"):
            raise requests.ConnectionError("PAN01 is unreachable")
        return CertificateResponse()

    client.request = request
    result = client._system_certificate_data([
        {"hostname": "ise-pan01.example.net"},
        {"hostname": "ise-pan02.example.net"},
        {"hostname": "ise-psn01.example.net"},
    ])

    assert result["node_statuses"] == [
        {"name": "ise-pan01.example.net", "status": "unavailable"},
        {"name": "ise-pan02.example.net", "status": "green"},
        {"name": "ise-psn01.example.net", "status": "green"},
    ]
    assert "ise-pan02.example.net" in result["details"]
    assert "ise-psn01.example.net" in result["details"]
    assert "ise-pan01.example.net" not in result["details"]


def test_certificate_expiration_status_thresholds():
    today = date(2026, 8, 22)
    assert ISEClient._certificate_expiration_status("11/20/26", today) == "green"
    assert ISEClient._certificate_expiration_status("11/19/26", today) == "yellow"
    assert ISEClient._certificate_expiration_status("10/21/26", today) == "yellow"
    assert ISEClient._certificate_expiration_status("10/20/26", today) == "orange"
    assert ISEClient._certificate_expiration_status("08/23/26", today) == "orange"
    assert ISEClient._certificate_expiration_status("08/22/26", today) == "red"
    assert ISEClient._certificate_expiration_status("08/21/26", today) == "red"


def test_node_details_map_personas_roles_services_and_certificates():
    nodes = [{
        "hostname": "ise-pan01",
        "roles": ["PrimaryAdmin", "PrimaryMonitoring", "PolicyService"],
        "services": ["SESSION", "PROFILER"],
        "nodeStatus": "Connected",
    }]
    certificate_data = {
        "node_statuses": [{"name": "ise-pan01", "status": "yellow"}],
        "certificates_by_node": {
            "ise-pan01": [{"friendly_name": "ise-pan01_LTMA", "expiration": "11/01/26"}]
        },
    }

    assert ISEClient._node_details(nodes, certificate_data) == [{
        "hostname": "ise-pan01",
        "personas": ["Administration", "Monitoring", "Policy Service"],
        "roles": ["PRI(A)", "PRI(M)"],
        "services": ["SESSION", "PROFILER"],
        "certificates": [{"friendly_name": "ise-pan01_LTMA", "expiration": "11/01/26"}],
        "certificate_status": "yellow",
        "node_status": "Connected",
    }]


def test_empty_roles_with_session_and_profiler_identifies_psn():
    nodes = [{
        "hostname": "ise-psn01",
        "roles": [],
        "services": ["Session", "Profiler", "DeviceAdmin"],
        "nodeStatus": "Connected",
    }]

    result = ISEClient._node_details(nodes, {"node_statuses": [], "certificates_by_node": {}})

    assert result[0]["personas"] == ["Policy Service"]
