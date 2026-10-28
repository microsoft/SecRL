# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Conservative entity keys and lossless alert-entity traversal."""

from __future__ import annotations

import ipaddress
import json
import re
from functools import lru_cache
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit


GUID_KINDS = {"directory_object", "application_id", "message_id", "signin_request", "graph_request"}
LOWER_KINDS = {"host", "upn", "domain", "sid", "azure_resource", "mde_device",
               "sha256", "sha1", "md5", "alert", "provider_alert"}
SCOPED_ALERT_TYPES = {
    "iotdevice", "K8s-cluster", "K8s-namespace", "K8s-service", "K8s-pod",
    "container", "blob-container",
}


@lru_cache(maxsize=8192)
def normalize_entity(kind: str, value: str | None) -> str | None:
    if value is None or not value.strip() or value.strip() in ("-", "N/A", "null"):
        return None
    value = value.strip()
    if kind == "mac_reference":
        mac = value.replace("-", ":").lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) or mac in (
            "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff",
        ):
            return None
        return mac
    if kind in ("ip", "ip_port"):
        if kind == "ip_port":
            if value.startswith("["):
                match = re.fullmatch(r"\[([^\]]+)\](?::\d+)?", value)
                if not match:
                    return None
                value = match[1]
            elif value.count(":") == 1 and "." in value:
                value, port = value.rsplit(":", 1)
                if not port.isdigit():
                    return None
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return str(address)
    if kind in GUID_KINDS:
        return value.lower() if re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value) else None
    if kind in ("sha256", "sha1", "md5"):
        length = {"sha256": 64, "sha1": 40, "md5": 32}[kind]
        return value.lower() if re.fullmatch(f"[0-9a-fA-F]{{{length}}}", value) else None
    if kind == "upn":
        if not re.fullmatch(r"[^@\s]+@[^@\s]+", value):
            return None
    if kind == "host":
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
            return None
        try:
            ipaddress.ip_address(value)
            return None
        except ValueError:
            pass
    if kind == "sid" and not re.fullmatch(r"S-\d+(?:-\d+)+", value, re.I):
        return None
    if kind in ("url", "address"):
        if "://" in value:
            try:
                parts = urlsplit(value)
                if not parts.hostname or parts.username or parts.password:
                    return None
                port = parts.port
            except ValueError:
                return None
            host = parts.hostname.lower()
            if ":" in host:
                host = "[" + host + "]"
            netloc = host + (f":{port}" if port is not None else "")
            return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))
        if kind == "url":
            return None
        if any(character in value for character in ("/", "?", "#")):
            try:
                parts = urlsplit("//" + value)
                if not parts.hostname or parts.username or parts.password:
                    return None
                host = normalize_entity("domain", parts.hostname)
                if host is None:
                    return None
                port = parts.port
            except ValueError:
                return None
            return host + (f":{port}" if port is not None else "") + parts.path + (
                "?" + parts.query if parts.query else ""
            ) + ("#" + parts.fragment if parts.fragment else "")
        return normalize_entity("domain", value)
    if kind == "domain":
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.?", value) or "." not in value:
            return None
        try:
            ipaddress.ip_address(value)
            return None
        except ValueError:
            return value.lower().rstrip(".")
    if kind == "cloud_application_id":
        return str(int(value)) if value.isdigit() else None
    if kind == "process":
        try:
            parts = json.loads(value)
            if not isinstance(parts, dict) or type(parts.get("pid")) is bool:
                return None
            created = datetime.fromisoformat(parts["created"].replace("Z", "+00:00"))
            pid = str(parts["pid"])
            if not pid.isdigit() or created.tzinfo is None or created.utcoffset() is None or int(pid) <= 0:
                return None
            host = normalize_entity("host", parts["host"])
            if host is None:
                return None
            return json.dumps([host, int(pid), created.astimezone(timezone.utc).isoformat(timespec="microseconds")],
                              separators=(",", ":"))
        except (KeyError, ValueError, TypeError):
            return None
    if kind == "azure_resource" and not value.startswith("/"):
        return None
    return value.lower() if kind in LOWER_KINDS else value


def effective_kind(kind: str, value: str) -> str:
    if kind == "ip_port":
        return "ip"
    if kind == "address":
        return "url" if "://" in value else "url_reference" if any(c in value for c in ("/", "?", "#")) else "domain"
    return kind


def graph_api_targets(uri: str | None) -> str:
    if not uri:
        return "[]"
    try:
        parts = urlsplit(uri)
    except ValueError:
        return "[]"
    if parts.scheme.lower() != "https" or parts.hostname != "graph.microsoft.com" or parts.username or parts.password:
        return "[]"
    segments = parts.path.split("/")
    targets = []
    for i, segment in enumerate(segments[:-1]):
        if segment in ("users", "groups", "directoryObjects", "servicePrincipals", "applications", "devices"):
            identifier = normalize_entity("directory_object", segments[i + 1])
            if identifier:
                targets.append({"id": identifier, "collection": segment, "segment": i + 1})
    return json.dumps(targets)


def command_references(command: str | None) -> str:
    if not command:
        return "[]"
    matches = []
    # These are lexical references, never proof of file access or code execution.
    pattern = r'https?://[^\s\'"<>]+|(?:[A-Za-z]:\\|/)[^\s\'"<>:]*\.(?:exe|dll|ps1|bat|sh|py|txt)(?![\w.])|[\w.-]+\.(?:exe|dll|ps1|bat|sh|py|txt)(?![\w.])'
    for match in re.finditer(pattern, command, re.I):
        value = match[0]
        kind = "address" if re.match(r"https?://", value, re.I) else "file_reference"
        matches.append({"kind": kind, "value": value, "offset": match.start()})
    return json.dumps(matches)


def url_hostname(value: str | None) -> str | None:
    if not value or "://" not in value:
        return None
    try:
        parts = urlsplit(value)
        return normalize_entity("domain", parts.hostname) if not parts.username and not parts.password else None
    except ValueError:
        return None


def resolve_entity_object(value: object, definitions: dict) -> dict:
    seen: set[str] = set()
    while isinstance(value, dict) and "$ref" in value:
        ref = str(value["$ref"])
        if ref in seen:
            return {}
        seen.add(ref)
        value = definitions.get(ref)
    return value if isinstance(value, dict) else {}


def scoped_alert_reference(item: dict, definitions: dict) -> tuple[str, str, str] | None:
    """Scope named references by their explicit source parents, not observation proximity."""
    kind = item.get("Type")

    def child(parent: dict, field: str, expected_type: str) -> dict:
        value = resolve_entity_object(parent.get(field), definitions)
        return value if value.get("Type") == expected_type else {}

    def resource(parent: dict, field: str) -> str | None:
        value = child(parent, field, "azure-resource").get("ResourceId")
        return normalize_entity("azure_resource", value) if isinstance(value, str) else None

    def named(value: dict) -> str | None:
        name = value.get("Name")
        return name if isinstance(name, str) and name.strip() else None

    if kind == "K8s-cluster":
        arm = resource(item, "CloudResource")
        return ("azure_resource", arm, "CloudResource.ResourceId") if arm else None
    if kind == "iotdevice":
        arm = resource(item, "IoTHub")
        device = item.get("DeviceId")
        device = normalize_entity("iot_device_id", device) if isinstance(device, str) else None
        if not arm or not device:
            return None
        return "iot_device", json.dumps([arm, device], separators=(",", ":")), "IoTHub.ResourceId+DeviceId"
    if kind == "blob-container":
        arm, name = resource(item, "StorageResource"), named(item)
        if not arm or not name:
            return None
        return "blob_container_reference", json.dumps([arm, name], separators=(",", ":")), "StorageResource.ResourceId+Name"
    pod = child(item, "Pod", "K8s-pod") if kind == "container" else item
    namespace = item if kind == "K8s-namespace" else child(pod, "Namespace", "K8s-namespace")
    cluster = child(namespace, "Cluster", "K8s-cluster")
    arm, ns_name = resource(cluster, "CloudResource"), named(namespace)
    if not arm or not ns_name:
        return None
    parts = [arm, ns_name]
    paths = ["Cluster.CloudResource.ResourceId", "Name"]
    if kind != "K8s-namespace":
        name = named(pod)
        if not name:
            return None
        parts.append(name)
        paths = ["Namespace." + p for p in paths] + ["Name"]
    if kind == "container":
        name = named(item)
        if not name:
            return None
        parts.append(name)
        paths = ["Pod." + p for p in paths] + ["Name"]
    target = {
        "K8s-namespace": "k8s_namespace_reference", "K8s-service": "k8s_service_reference",
        "K8s-pod": "k8s_pod_reference", "container": "k8s_container_reference",
    }.get(kind)
    return (target, json.dumps(parts, separators=(",", ":")), "+".join(paths)) if target else None


def walk_alert_entities(text: str | None) -> tuple[list[tuple[str, str, str]], list[tuple[str, str]]]:
    """Return (kind,value,JSON path) mentions; resolve $refs without guessing missing identity."""
    if not text:
        return [], []
    roots = json.loads(text)
    if not isinstance(roots, list):
        raise ValueError("Entities must be a JSON array")
    definitions = {}
    issues = []

    def index(item: object, path: str, depth: int = 0) -> None:
        if depth > 64:
            raise ValueError("alert entity structure exceeds depth limit")
        if isinstance(item, dict):
            if "$id" in item:
                key = str(item["$id"])
                if key in definitions and definitions[key] != item:
                    raise ValueError(f"conflicting entity definition {key}")
                definitions[key] = item
            for key, value in item.items():
                index(value, path + "." + key, depth + 1)
        elif isinstance(item, list):
            for i, value in enumerate(item):
                index(value, f"{path}[{i}]", depth + 1)

    index(roots, "$")
    mentions = []
    hosts = {r.get("FQDN") or r.get("HostName") for r in roots if isinstance(r, dict) and r.get("Type") == "host"}
    hosts.discard(None)
    process_host = next(iter(hosts)) if len(hosts) == 1 else None
    type_fields = {
        "host": (("FQDN", "host"), ("HostName", "host"), ("MdatpDeviceId", "mde_device"), ("AadDeviceId", "directory_object"),
                 ("LastIpAddress", "ip"), ("LastExternalIpAddress", "ip")),
        "account": (("UserPrincipalName", "upn"), ("AadUserId", "directory_object"), ("Sid", "sid"),
                    ("Name", "account_name_reference")),
        "ip": (("Address", "ip"),), "url": (("Url", "address"),), "dns": (("DomainName", "domain"),),
        "file": (("Name", "file_reference"),),
        "mailMessage": (("NetworkMessageId", "message_id"), ("Sender", "upn"), ("Recipient", "upn"), ("SenderIP", "ip")),
        "mailCluster": (),
        "mailbox": (("Upn", "upn"), ("MailboxPrimaryAddress", "upn"), ("AadId", "directory_object")),
        "cloud-application": (("AppId", "cloud_application_id"), ("Name", "application_name_reference"),
                              ("InstanceName", "application_name_reference")),
        "oauth-application": (("OAuthAppId", "application_id"), ("OAuthObjectId", "directory_object")),
        "azure-resource": (("ResourceId", "azure_resource"),),
        "cloud-logon-request": (("RequestId", "signin_request"),),
        "cloud-logon-session": (("SessionId", "cloud_session"),),
        "security-group": (("SID", "sid"),), "registry-key": (("Key", "registry_reference"),),
        "registry-value": (("Name", "registry_value_name_reference"),),
        "nic": (("MacAddress", "mac_reference"),),
        "iotdevice": (("DeviceName", "device_name_reference"),),
        "container-image": (("ImageId", "container_image_reference"),),
    }

    def walk(item: object, path: str, active: frozenset[str], depth: int = 0) -> None:
        if depth > 64:
            raise ValueError("alert entity structure exceeds depth limit")
        if isinstance(item, list):
            for i, value in enumerate(item):
                walk(value, f"{path}[{i}]", active, depth + 1)
        elif isinstance(item, dict):
            if "$ref" in item:
                ref = str(item["$ref"])
                if ref in active:
                    issues.append((path, "cyclic_entity_reference"))
                elif ref not in definitions:
                    issues.append((path, "unresolved_entity_reference"))
                else:
                    walk(definitions[ref], path, active | {ref}, depth + 1)
                return
            kind = item.get("Type")
            if kind in SCOPED_ALERT_TYPES:
                scoped = scoped_alert_reference(item, definitions)
                if scoped:
                    target_kind, value, fields = scoped
                    mentions.append((target_kind, value, path + "." + fields))
                else:
                    issues.append((path, "incomplete_scoped_entity_reference:" + kind))
            for field, target_kind in type_fields.get(kind, ()):
                value = item.get(field)
                if target_kind == "ip" and isinstance(value, dict):
                    value = value.get("Address")
                if isinstance(value, (str, int)) and not isinstance(value, bool):
                    mentions.append((target_kind, str(value), path + "." + field))
            array_fields = {
                "mailMessage": (("Urls", "address"),),
                "mailCluster": (("NetworkMessageIds", "message_id"),),
            }.get(kind, ())
            for field, target_kind in array_fields:
                values = item.get(field) or []
                if not isinstance(values, list):
                    issues.append((path + "." + field, "invalid_entity_array"))
                    continue
                for i, value in enumerate(values):
                    if isinstance(value, str):
                        mentions.append((target_kind, value, path + f".{field}[{i}]"))
            if kind == "account" and item.get("Name") and item.get("UPNSuffix") and not item.get("UserPrincipalName"):
                mentions.append(("upn", str(item["Name"]) + "@" + str(item["UPNSuffix"]), path + ".Name+UPNSuffix"))
            if kind == "process":
                if process_host and item.get("ProcessId") and item.get("CreationTimeUtc"):
                    value = json.dumps({"host": process_host, "pid": item["ProcessId"], "created": item["CreationTimeUtc"]})
                    mentions.append(("process", value, path + ".ProcessId+CreationTimeUtc"))
                else:
                    issues.append((path, "incomplete_or_ambiguous_process_identity"))
                if isinstance(item.get("CommandLine"), str):
                    for reference in json.loads(command_references(item["CommandLine"])):
                        mentions.append((reference["kind"], reference["value"], path + f".CommandLine@{reference['offset']}"))
            if item.get("Algorithm") in ("SHA256", "SHA1", "MD5") and item.get("Value"):
                mentions.append((item["Algorithm"].lower(), str(item["Value"]), path + ".Value"))
            if kind not in type_fields and kind not in SCOPED_ALERT_TYPES and kind not in (None, "process", "filehash"):
                issues.append((path, f"unmapped_entity_type:{kind}"))
            for key, value in item.items():
                if key not in ("$id", "$ref"):
                    walk(value, path + "." + key, active, depth + 1)

    walk(roots, "$", frozenset())
    return sorted(set(mentions)), issues
