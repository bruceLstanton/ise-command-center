import time
import re
from datetime import date
from urllib.parse import quote, urljoin, urlparse
import requests


class ISEClient:
    def __init__(self, cluster, password, username=None):
        self.cluster = cluster
        self.session = requests.Session()
        self.session.auth = (username or cluster.username, password)
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        self._active_base_url = self._preferred_base_url()

    @property
    def verify(self):
        return self.cluster.ca_bundle or self.cluster.verify_tls

    def request(self, method, path, **kwargs):
        fallback_statuses = kwargs.pop("fallback_statuses", ())
        base_urls = [self._active_base_url]
        for candidate in (
            getattr(self.cluster, "pan01_base_url", None) or getattr(self.cluster, "base_url", None),
            getattr(self.cluster, "pan02_base_url", None),
        ):
            if candidate and candidate not in base_urls:
                base_urls.append(candidate)

        last_error = None
        for base_url in base_urls:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = self.session.request(
                    method, url, timeout=(5, 25), verify=self.verify, **kwargs
                )
                if (
                    getattr(response, "status_code", None) in fallback_statuses
                    and base_url != base_urls[-1]
                ):
                    continue
                self._active_base_url = base_url
                return response
            except requests.RequestException as exc:
                last_error = exc
        raise last_error

    def _preferred_base_url(self):
        """Prefer the configured URL matching the last known Primary PAN."""
        pan01 = getattr(self.cluster, "pan01_base_url", None) or getattr(
            self.cluster, "base_url", None
        )
        pan02 = getattr(self.cluster, "pan02_base_url", None)
        primary = str(getattr(self.cluster, "primary_pan", "") or "").strip().lower()
        if not pan02 or not primary:
            return pan01

        primary_short = primary.split(".", 1)[0]
        pan02_host = (urlparse(pan02).hostname or "").lower()
        pan02_short = pan02_host.split(".", 1)[0]
        if primary in {pan02_host, pan02_short} or primary_short in {pan02_host, pan02_short}:
            return pan02

        # This also supports PAN URLs configured with IP addresses: ISE's Primary
        # PAN name convention identifies PAN02 even when its URL has no hostname.
        if re.search(r"pan[-_]?0?2(?:\.|$)", primary):
            return pan02
        return pan01

    def health(self):
        started = time.monotonic()
        response = self.request("GET", "/api/v1/deployment/node")
        latency = round((time.monotonic() - started) * 1000)
        response.raise_for_status()
        deployment = response.json()
        nodes = self._records(deployment)
        version_data = self._optional_json("/ers/config/op/systemconfig/iseversion")
        patch_data = self._optional_json("/api/v1/patch")
        backup_status = self._backup_status(
            "/api/v1/backup-restore/config/last-backup-status",
        )
        version = self._find(patch_data, "iseVersion") or self._find(
            version_data, "iseVersion", "productVersion", "softwareVersion", "version"
        )
        patches = self._find_value(patch_data, "patchVersion")
        latest_patch = self._latest_patch(patches)
        certificate_data = self._system_certificate_data(nodes)
        node_details = self._node_details(nodes, certificate_data)
        snapshot = {
            "latency_ms": latency,
            "node_count": len(nodes) or self._find_int(deployment, "total", "count"),
            "version": version,
            "latest_patch": latest_patch,
            "primary_pan": self._primary_pan(nodes),
            "node_statuses": self._node_statuses(nodes),
            "replication_status": self._replication(nodes),
            "backup_status": backup_status,
            "saml_cert_expirations": certificate_data["details"],
            "system_certificate_statuses": certificate_data["node_statuses"],
            "node_details": node_details,
        }
        return snapshot

    def certificate_inventory(self):
        """Return the full system and trusted certificate inventories from ISE."""
        deployment_response = self.request("GET", "/api/v1/deployment/node")
        deployment_response.raise_for_status()
        nodes = self._records(deployment_response.json())

        system_certificates = []
        errors = []
        for index, node in enumerate(nodes, 1):
            hostname = str(
                node.get("hostname") or node.get("name") or node.get("fqdn") or f"Node {index}"
            )
            try:
                response = self.request(
                    "GET",
                    f"/api/v1/certs/system-certificate/{quote(hostname, safe='')}",
                    fallback_statuses=(404, 405, 500, 502, 503, 504),
                )
                response.raise_for_status()
                for certificate in self._records(response.json()):
                    if not self._matches_certificate_filter(certificate):
                        continue
                    system_certificates.append(
                        self._certificate_inventory_item(
                            certificate, hostname=hostname, status_from_expiration=True
                        )
                    )
            except (requests.RequestException, ValueError) as exc:
                errors.append(f"System certificates for {hostname}: {exc}")

        trusted_certificates = []
        try:
            response = self.request(
                "GET",
                "/api/v1/certs/trusted-certificate",
                fallback_statuses=(404, 405, 500, 502, 503, 504),
            )
            response.raise_for_status()
            trusted_certificates = [
                self._certificate_inventory_item(certificate, usage_field="trustedFor")
                for certificate in self._records(response.json())
                if self._matches_certificate_filter(certificate, usage_field="trustedFor")
            ]
        except (requests.RequestException, ValueError) as exc:
            errors.append(f"Trusted certificates: {exc}")

        return {
            "system_certificates": system_certificates,
            "trusted_certificates": trusted_certificates,
            "errors": errors,
        }

    def import_trusted_certificate(self, certificate_data, **settings):
        payload = {
            "data": certificate_data,
            "allowBasicConstraintCAFalse": False,
            "allowOutOfDateCert": False,
            "allowSHA1Certificates": False,
            "trustForIseAuth": bool(settings.get("trust_for_ise_auth")),
            "trustForClientAuth": bool(settings.get("trust_for_client_auth")),
            "trustForCertificateBasedAdminAuth": bool(
                settings.get("trust_for_certificate_based_admin_auth")
            ),
            "trustForCiscoServicesAuth": bool(settings.get("trust_for_cisco_services_auth")),
            "validateCertificateExtensions": bool(
                settings.get("validate_certificate_extensions")
            ),
        }
        if settings.get("name"):
            payload["name"] = settings["name"]
        if settings.get("description"):
            payload["description"] = settings["description"]
        response = self.request(
            "POST", "/api/v1/certs/trusted-certificate/import", json=payload
        )
        if not response.ok:
            detail = None
            try:
                error_payload = response.json()
                detail = self._find(error_payload, "message", "error", "detail")
            except ValueError:
                detail = response.text.strip() if response.text else None
            detail = str(detail)[:500] if detail else "ISE rejected the import request."
            raise RuntimeError(f"ISE returned HTTP {response.status_code}: {detail}")
        try:
            return response.json()
        except ValueError:
            return {}

    def import_system_certificate(self, certificate_data, private_key_data, password, **settings):
        payload = {
            "data": certificate_data,
            "privateKeyData": private_key_data,
            "password": password,
            "allowExtendedValidity": bool(settings.get("allow_extended_validity")),
            "allowOutOfDateCert": False,
            "allowReplacementOfCertificates": False,
            "allowReplacementOfPortalGroupTag": False,
            "allowSHA1Certificates": False,
            "allowWildCardCertificates": bool(settings.get("allow_wildcard_certificates")),
            "allowRoleTransferForSameSubject": True,
            "allowPortalTagTransferForSameSubject": True,
            "portalGroupTag": "Default Portal Certificate Group",
            "admin": bool(settings.get("admin")),
            "eap": bool(settings.get("eap")),
            "ims": bool(settings.get("ims")),
            "portal": bool(settings.get("portal")),
            "pxgrid": bool(settings.get("pxgrid")),
            "radius": bool(settings.get("radius")),
            "saml": bool(settings.get("saml")),
            "validateCertificateExtensions": bool(settings.get("validate_certificate_extensions")),
        }
        if settings.get("name"):
            payload["name"] = settings["name"]
        response = self.request(
            "POST", "/api/v1/certs/system-certificate/import", json=payload
        )
        if not response.ok:
            detail = None
            try:
                detail = self._find(response.json(), "message", "error", "detail")
            except ValueError:
                detail = response.text.strip() if response.text else None
            detail = str(detail)[:500] if detail else "ISE rejected the import request."
            raise RuntimeError(f"ISE returned HTTP {response.status_code}: {detail}")
        try:
            return response.json()
        except ValueError:
            return {}

    @classmethod
    def _certificate_inventory_item(
        cls, certificate, hostname=None, usage_field="usedBy", status_from_expiration=False
    ):
        used_by = certificate.get(usage_field)
        if isinstance(used_by, list):
            used_by = ", ".join(str(value) for value in used_by)
        expiration = cls._format_ise_date(certificate.get("expirationDate"))
        status = certificate.get("status") or "—"
        if status_from_expiration and expiration:
            month, day, year = (int(part) for part in expiration.split("/"))
            expiration_date = date(2000 + year, month, day)
            status = "Active" if expiration_date >= date.today() else "Expired"
        return {
            "hostname": hostname,
            "friendly_name": certificate.get("friendlyName") or certificate.get("name") or "Unnamed certificate",
            "subject": certificate.get("issuedTo") or certificate.get("subject") or "Unavailable",
            "issued_by": certificate.get("issuedBy") or "Unavailable",
            "used_by": used_by or "—",
            "expiration": expiration or "Unavailable",
            "status": status,
        }

    @staticmethod
    def _matches_certificate_filter(certificate, usage_field="usedBy"):
        return (
            "ltma" in str(certificate.get("issuedBy") or "").lower()
            and "admin" in str(certificate.get(usage_field) or "").lower()
        )

    def _optional_json(self, path):
        try:
            response = self.request("GET", path)
            if response.ok:
                return response.json()
        except (requests.RequestException, ValueError):
            pass
        return {}

    def _backup_status(self, path):
        """Keep a successful JSON null distinct from an API failure."""
        try:
            response = self.request("GET", path)
            if not response.ok:
                return None
            payload = response.json()
            if payload is None:
                return "No history of backups"
            return self._backup_summary(payload)
        except (requests.RequestException, ValueError):
            return None

    def _saml_expirations(self, nodes):
        return self._system_certificate_data(nodes)["details"]

    def _system_certificate_data(self, nodes):
        node_certificates = []
        node_statuses = []
        certificates_by_node = {}
        successful_requests = 0
        queried_nodes = 0
        for node in nodes:
            hostname = node.get("hostname") or node.get("name") or node.get("fqdn")
            if not hostname:
                continue
            queried_nodes += 1
            try:
                response = self.request(
                    "GET",
                    f"/api/v1/certs/system-certificate/{quote(str(hostname), safe='')}",
                    fallback_statuses=(404, 405, 500, 502, 503, 504),
                )
                if not response.ok:
                    node_statuses.append({"name": str(hostname), "status": "unavailable"})
                    continue
                certificates = self._records(response.json())
                successful_requests += 1
                matching_certificates = []
                for certificate in certificates:
                    if not self._matches_certificate_filter(certificate):
                        continue
                    formatted = self._format_ise_date(certificate.get("expirationDate"))
                    if formatted:
                        friendly_name = str(certificate.get("friendlyName") or "").strip()
                        matching_certificates.append((friendly_name or "Unnamed certificate", formatted))
                if matching_certificates:
                    node_certificates.append((str(hostname), matching_certificates))
                    certificates_by_node[str(hostname)] = [
                        {"friendly_name": name, "expiration": expiration}
                        for name, expiration in matching_certificates
                    ]
                    certificate_statuses = [
                        self._certificate_expiration_status(item[1]) for item in matching_certificates
                    ]
                    severity = {"green": 0, "yellow": 1, "orange": 2, "red": 3}
                    node_statuses.append({
                        "name": str(hostname),
                        "status": max(certificate_statuses, key=severity.get),
                    })
                else:
                    node_statuses.append({"name": str(hostname), "status": "unavailable"})
            except (requests.RequestException, ValueError):
                node_statuses.append({"name": str(hostname), "status": "unavailable"})
                continue
        if not queried_nodes:
            return {"details": None, "node_statuses": [], "certificates_by_node": {}}
        if not successful_requests:
            return {
                "details": None,
                "node_statuses": node_statuses,
                "certificates_by_node": certificates_by_node,
            }
        if not node_certificates:
            return {
                "details": "None found",
                "node_statuses": node_statuses,
                "certificates_by_node": certificates_by_node,
            }
        lines = []
        for hostname, certificates in node_certificates:
            lines.append(hostname)
            lines.extend(f"• {friendly_name} — {expiration}" for friendly_name, expiration in certificates)
        return {
            "details": "\n".join(lines),
            "node_statuses": node_statuses,
            "certificates_by_node": certificates_by_node,
        }

    @staticmethod
    def _certificate_expiration_status(formatted_date, today=None):
        month, day, year = (int(part) for part in formatted_date.split("/"))
        days_remaining = (date(2000 + year, month, day) - (today or date.today())).days
        if days_remaining >= 90:
            return "green"
        if days_remaining >= 60:
            return "yellow"
        if days_remaining >= 1:
            return "orange"
        return "red"

    @classmethod
    def _node_details(cls, nodes, certificate_data):
        certificate_statuses = {
            item["name"]: item["status"] for item in certificate_data.get("node_statuses", [])
        }
        certificates = certificate_data.get("certificates_by_node", {})
        details = []
        for index, node in enumerate(nodes, 1):
            hostname = str(node.get("hostname") or node.get("name") or node.get("fqdn") or f"Node {index}")
            roles = cls._as_list(node.get("roles") or node.get("role"))
            services = cls._as_list(
                node.get("services") or node.get("serviceNames") or node.get("service")
            )
            personas = cls._as_list(node.get("personas") or node.get("persona"))
            if not personas:
                normalized_roles = [str(role).lower().replace("_", "").replace("-", "") for role in roles]
                if any("admin" in role for role in normalized_roles):
                    personas.append("Administration")
                if any("monitor" in role for role in normalized_roles):
                    personas.append("Monitoring")
                if any("policyservice" in role for role in normalized_roles):
                    personas.append("Policy Service")
                normalized_services = {service.strip().lower() for service in services}
                if not roles and {"session", "profiler"}.issubset(normalized_services):
                    personas.append("Policy Service")
            role_names = {
                "primaryadmin": "PRI(A)",
                "secondaryadmin": "SEC(A)",
                "primarymonitoring": "PRI(M)",
                "secondarymonitoring": "SEC(M)",
            }
            display_roles = []
            for role in roles:
                normalized = str(role).lower().replace("_", "").replace("-", "")
                if normalized in role_names:
                    display_roles.append(role_names[normalized])
            details.append({
                "hostname": hostname,
                "personas": personas,
                "roles": display_roles,
                "services": services,
                "certificates": certificates.get(hostname, []),
                "certificate_status": certificate_statuses.get(hostname, "unavailable"),
                "node_status": str(node.get("nodeStatus") or "Unknown"),
            })
        return details

    @staticmethod
    def _as_list(value):
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
        if value not in (None, ""):
            return [item.strip() for item in str(value).split(",") if item.strip()]
        return []

    @staticmethod
    def _format_ise_date(value):
        if not value:
            return None
        months = {name: number for number, name in enumerate(
            ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
        )}
        match = re.search(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\b.*\b(\d{4})$", str(value).strip())
        if match and match.group(1) in months:
            return f"{months[match.group(1)]:02d}/{int(match.group(2)):02d}/{int(match.group(3)) % 100:02d}"
        iso = re.match(r"^(\d{4})-(\d{2})-(\d{2})", str(value).strip())
        if iso:
            return f"{iso.group(2)}/{iso.group(3)}/{int(iso.group(1)) % 100:02d}"
        return None

    @staticmethod
    def _records(payload):
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("response", "items", "nodes", "data"):
                value = payload.get(key)
                if isinstance(value, list):
                    return value
        return []

    @classmethod
    def _find(cls, payload, *keys):
        if isinstance(payload, dict):
            for key in keys:
                value = payload.get(key)
                if value not in (None, "", [], {}):
                    return str(value)
            for value in payload.values():
                found = cls._find(value, *keys)
                if found:
                    return found
        elif isinstance(payload, list):
            for value in payload:
                found = cls._find(value, *keys)
                if found:
                    return found
        return None

    @classmethod
    def _find_value(cls, payload, key):
        if isinstance(payload, dict):
            if key in payload:
                return payload[key]
            for value in payload.values():
                found = cls._find_value(value, key)
                if found is not None:
                    return found
        elif isinstance(payload, list):
            for value in payload:
                found = cls._find_value(value, key)
                if found is not None:
                    return found
        return None

    @classmethod
    def _find_int(cls, payload, *keys):
        value = cls._find(payload, *keys)
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @classmethod
    def _primary_pan(cls, nodes):
        for node in nodes:
            roles = node.get("roles") or [node.get("role", "")]
            roles = [str(role).lower().replace("_", "").replace("-", "") for role in roles]
            if any(role in ("primaryadmin", "primarypan") for role in roles):
                return str(node.get("name") or node.get("hostname") or node.get("fqdn") or "Primary PAN")
        return None

    @classmethod
    def _node_statuses(cls, nodes):
        statuses = []
        for index, node in enumerate(nodes, 1):
            name = node.get("hostname") or node.get("name") or node.get("fqdn") or f"Node {index}"
            status = node.get("nodeStatus") or cls._find(
                node, "replicationStatus", "replicationState", "syncStatus"
            ) or "Unknown"
            statuses.append({"name": str(name), "status": str(status)})
        return statuses

    @classmethod
    def _replication(cls, nodes):
        states = [cls._find(node, "replicationStatus", "replicationState", "syncStatus") for node in nodes]
        states = [state for state in states if state]
        if states:
            normalized = {state.lower().replace("_", " ") for state in states}
            return "In sync" if all("sync" in state and "out" not in state for state in normalized) else ", ".join(sorted(set(states)))

        # ISE 3.3 exposes replication state through DeploymentNode.nodeStatus.
        # Its documented values include NotInSync and ReplicationStopped.
        node_states = [str(node.get("nodeStatus", "")).strip() for node in nodes]
        node_states = [state for state in node_states if state]
        if not node_states:
            return None
        counts = {state: node_states.count(state) for state in set(node_states)}
        if set(counts) == {"Connected"}:
            return "In sync"
        if set(counts) == {"NotApplicable"}:
            return "Not applicable"
        priority = (
            ("ReplicationStopped", "Replication stopped"),
            ("NotInSync", "Not in sync"),
            ("RegistrationFailed", "Registration failed"),
            ("Disconnected", "Disconnected"),
            ("NotUpgraded", "Not upgraded"),
            ("InProgress", "Synchronization in progress"),
        )
        problems = [f"{label} ({counts[state]})" for state, label in priority if counts.get(state)]
        return "; ".join(problems) if problems else ", ".join(sorted(counts))

    @staticmethod
    def _latest_patch(patches):
        if isinstance(patches, list):
            numbers = []
            for patch in patches:
                if isinstance(patch, dict):
                    patch = patch.get("patchNumber")
                try:
                    numbers.append(int(patch))
                except (TypeError, ValueError):
                    continue
            return f"Patch {max(numbers)}" if numbers else "No patch installed"
        if patches not in (None, "", []):
            return str(patches)
        return None

    @classmethod
    def _license_summary(cls, payload):
        if not payload:
            return None
        states = []
        tiers = cls._find_value(payload, "tierState") or cls._find_value(payload, "response")
        if not tiers and isinstance(payload, list):
            tiers = payload
        if isinstance(tiers, list):
            for tier in tiers:
                if isinstance(tier, dict):
                    name = tier.get("tier") or tier.get("name") or tier.get("licenseTier")
                    status = tier.get("compliance") or tier.get("status") or tier.get("state")
                    if name and status:
                        states.append(f"{name}: {status}")
        if states:
            return "; ".join(states)
        return cls._find(payload, "compliance", "status", "registrationStatus", "connectionStatus")

    @classmethod
    def _backup_summary(cls, payload):
        if not payload:
            return None
        if cls._contains_null_key(payload, "justComplete"):
            return "No history of backups"
        status = cls._find(payload, "backupStatus", "status", "state")
        message = cls._find(payload, "message")
        error = cls._find_value(payload, "error")
        timestamp = cls._find(payload, "endTime", "completionTime", "lastBackupTime", "startDate")

        message_lower = (message or "").lower()
        error_value = str(error).strip().lower() if error is not None else ""
        failed = (
            (status or "").upper() == "ERROR"
            or "fail" in message_lower
            or "error" in message_lower
            or error_value not in ("", "false", "no", "0", "none", "null")
        )
        if failed:
            reason = message or "Backup failed"
            if reason.lower().startswith("backup failed:"):
                reason = reason.split(":", 1)[1].strip()
            return f"Failed · {reason[:1].upper() + reason[1:]}"
        if (status or "").upper() == "COMPLETED":
            return " · ".join(value for value in ("Successful", timestamp) if value)
        if (status or "").upper() == "IN_PROGRESS":
            return " · ".join(value for value in ("In progress", timestamp) if value)
        return " · ".join(value for value in (status, timestamp, message) if value) or None

    @classmethod
    def _contains_null_key(cls, payload, key):
        if isinstance(payload, dict):
            if key in payload and payload[key] is None:
                return True
            return any(cls._contains_null_key(value, key) for value in payload.values())
        if isinstance(payload, list):
            return any(cls._contains_null_key(value, key) for value in payload)
        return False

    def list_network_devices(self, size=20):
        response = self.request("GET", "/ers/config/networkdevice", params={"size": size})
        response.raise_for_status()
        return response.json()

    def create_network_device(self, payload):
        response = self.request("POST", "/ers/config/networkdevice", json=payload)
        response.raise_for_status()
        return response.headers.get("Location")
