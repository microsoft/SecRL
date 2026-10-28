# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Explicit observation-participant rules; fields do not imply attack causality."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FieldRule:
    tables: tuple[str, ...]
    column: str
    kind: str
    role: str


ENDPOINT = (
    "DeviceProcessEvents", "DeviceFileEvents", "DeviceImageLoadEvents", "DeviceNetworkEvents",
    "DeviceEvents", "DeviceRegistryEvents", "DeviceLogonEvents", "DeviceInfo",
    "DeviceNetworkInfo", "DeviceFileCertificateInfo",
)
IDENTITY = ("IdentityLogonEvents", "IdentityQueryEvents", "IdentityDirectoryEvents")
SIGNINS = ("SigninLogs", "AADNonInteractiveUserSignInLogs", "AADServicePrincipalSignInLogs",
           "AADManagedIdentitySignInLogs")
MAIL = ("EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo", "EmailPostDeliveryEvents", "UrlClickEvents")
FIREWALL = (
    "AZFWApplicationRule", "AZFWApplicationRuleAggregation", "AZFWNetworkRule",
    "AZFWNetworkRuleAggregation", "AZFWNatRule", "AZFWNatRuleAggregation", "AZFWDnsQuery",
    "AZFWIdpsSignature", "AZFWThreatIntel", "AZFWFlowTrace",
)

FIELD_RULES = (
    *(FieldRule(ENDPOINT, col, kind, role) for col, kind, role in (
        ("DeviceName", "host", "device_host"), ("DeviceId", "mde_device", "device_id"),
        ("AccountSid", "sid", "subject_sid"), ("AccountUpn", "upn", "subject_upn"),
        ("AccountObjectId", "directory_object", "subject_object"),
        ("InitiatingProcessAccountSid", "sid", "initiator_sid"),
        ("InitiatingProcessAccountUpn", "upn", "initiator_upn"),
        ("InitiatingProcessAccountObjectId", "directory_object", "initiator_object"),
        ("SHA256", "sha256", "subject_content"), ("SHA1", "sha1", "subject_content"),
        ("InitiatingProcessSHA256", "sha256", "initiator_content"),
        ("InitiatingProcessSHA1", "sha1", "initiator_content"),
        ("RemoteIP", "ip", "remote_ip"), ("LocalIP", "ip", "local_ip"),
        ("RemoteUrl", "address", "remote_address"), ("RemoteDeviceName", "host", "remote_host_label"),
        ("FileOriginUrl", "address", "file_origin_address"), ("FileOriginIP", "ip", "file_origin_ip"),
        ("RequestSourceIP", "ip", "request_source_ip"),
        ("Signer", "signer", "signer"), ("Issuer", "signer", "certificate_issuer"),
    )),
    *(FieldRule(IDENTITY, col, kind, role) for col, kind, role in (
        ("DeviceName", "host", "source_host_label"), ("DestinationDeviceName", "host", "destination_host_label"),
        ("TargetDeviceName", "host", "target_host_label"), ("IPAddress", "ip", "source_ip"),
        ("DestinationIPAddress", "ip", "destination_ip"), ("AccountSid", "sid", "actor_sid"),
        ("AccountUpn", "upn", "actor_upn"), ("AccountObjectId", "directory_object", "actor_object"),
        ("TargetAccountUpn", "upn", "target_upn"), ("QueryTarget", "query_target", "query_target"),
    )),
    *(FieldRule(SIGNINS, col, kind, role) for col, kind, role in (
        ("Id", "signin_request", "request"), ("UserId", "directory_object", "user_object"),
        ("UserPrincipalName", "upn", "user_upn"), ("IPAddress", "ip", "source_ip"),
        ("AppId", "application_id", "client_app"), ("ServicePrincipalId", "directory_object", "service_principal"),
        ("ResourceServicePrincipalId", "directory_object", "resource_principal"),
        ("UniqueTokenIdentifier", "token", "token_identifier"),
        ("OriginalRequestId", "signin_request", "original_request"),
    )),
    *(FieldRule(("MicrosoftGraphActivityLogs",), col, kind, role) for col, kind, role in (
        ("AppId", "application_id", "client_app"), ("UserId", "directory_object", "user_object"),
        ("ServicePrincipalId", "directory_object", "service_principal"), ("IPAddress", "ip", "source_ip"),
        ("SignInActivityId", "token", "signin_token_reference"),
        ("RequestId", "graph_request", "request"), ("RequestUri", "url", "request_uri"),
    )),
    *(FieldRule(MAIL, col, kind, role) for col, kind, role in (
        ("NetworkMessageId", "message_id", "message"), ("SenderFromAddress", "upn", "sender_address"),
        ("SenderMailFromAddress", "upn", "envelope_sender"), ("RecipientEmailAddress", "upn", "recipient_address"),
        ("SenderIPv4", "ip", "sender_ip"), ("SenderIPv6", "ip", "sender_ip"),
        ("AccountUpn", "upn", "clicking_account"), ("IPAddress", "ip", "click_ip"),
        ("Url", "address", "url"), ("SHA256", "sha256", "attachment_content"),
    )),
    *(FieldRule(("CloudAppEvents",), col, kind, role) for col, kind, role in (
        ("AccountObjectId", "directory_object", "actor_object"), ("IPAddress", "ip", "source_ip"),
        ("ApplicationId", "cloud_application_id", "cloud_application"),
        ("ObjectId", "cloud_object", "activity_object"),
    )),
    *(FieldRule(("AADUserRiskEvents", "AADRiskyUsers"), col, kind, role) for col, kind, role in (
        ("UserId", "directory_object", "user_object"), ("UserPrincipalName", "upn", "user_upn"),
        ("RequestId", "signin_request", "signin_request"), ("IpAddress", "ip", "source_ip"),
    )),
    *(FieldRule(FIREWALL, col, kind, role) for col, kind, role in (
        ("SourceIp", "ip", "source_ip"), ("DestinationIp", "ip", "destination_ip"),
        ("TranslatedIp", "ip", "translated_ip"), ("Fqdn", "domain", "destination_domain"),
        ("QueryName", "domain", "dns_query_name"), ("TargetUrl", "address", "target_address"),
        ("_ResourceId", "azure_resource", "resource"),
    )),
    *(FieldRule(("AzureDiagnostics",), col, kind, role) for col, kind, role in (
        ("ResourceId", "azure_resource", "resource"), ("clientIp_s", "ip_port", "client_ip"),
        ("originIp_s", "ip_port", "origin_ip"), ("requestUri_s", "request_path", "request_path"),
        ("probeUrl_s", "address", "probe_url"), ("hostName_s", "host", "host_label"),
        ("CallerIPAddress", "ip_port", "caller_ip"), ("client_ip_s", "ip_port", "client_ip"),
    )),
    *(FieldRule(("OfficeActivity",), col, kind, role) for col, kind, role in (
        ("UserId", "upn", "actor_upn"), ("MailboxOwnerUPN", "upn", "mailbox_owner"),
        ("ClientIP", "ip_port", "client_ip"), ("OfficeObjectId", "office_object", "office_object"),
        ("ApplicationId", "application_id", "client_app"),
    )),
    FieldRule(("DeviceInfo",), "AadDeviceId", "directory_object", "aad_device"),
    FieldRule(("DeviceInfo",), "PublicIP", "ip", "public_ip"),
    FieldRule(("AlertEvidence",), "AlertId", "provider_alert", "provider_alert"),
    FieldRule(("AlertInfo",), "AlertId", "provider_alert", "provider_alert"),
    FieldRule(("Alert",), "ResourceId", "azure_resource", "reported_resource"),
    FieldRule(("Operation",), "SourceComputerId", "monitor_source_computer", "monitor_source_computer"),
    FieldRule(("SentinelAudit", "SentinelHealth"), "SentinelResourceId", "azure_resource", "reported_sentinel_resource"),
    FieldRule(("Usage",), "ResourceUri", "azure_resource", "usage_resource"),
    FieldRule(("Usage",), "LinkedResourceUri", "azure_resource", "linked_usage_resource"),
    *(FieldRule(("AlertEvidence",), col, kind, role) for col, kind, role in (
        ("DeviceName", "host", "evidence_host"), ("AccountUpn", "upn", "evidence_upn"),
        ("AccountSid", "sid", "evidence_sid"), ("AccountObjectId", "directory_object", "evidence_object"),
        ("SHA256", "sha256", "evidence_content"), ("SHA1", "sha1", "evidence_content"),
        ("RemoteIP", "ip", "evidence_ip"), ("LocalIP", "ip", "evidence_ip"),
        ("RemoteUrl", "address", "evidence_address"), ("NetworkMessageId", "message_id", "evidence_message"),
    )),
    *(FieldRule(("ThreatIntelligenceIndicator",), col, kind, role) for col, kind, role in (
        ("NetworkIP", "ip", "indicator_ip"), ("NetworkSourceIP", "ip", "indicator_source_ip"),
        ("NetworkDestinationIP", "ip", "indicator_destination_ip"), ("DomainName", "domain", "indicator_domain"),
        ("Url", "address", "indicator_address"),
    )),
    *(FieldRule(("IntuneDevices", "IntuneDeviceComplianceOrg"), col, kind, role) for col, kind, role in (
        ("DeviceId", "intune_device", "inventory_device"), ("DeviceName", "host", "inventory_host_label"),
        ("UserEmail", "upn", "inventory_user_email"), ("UPN", "upn", "inventory_upn"),
        ("UserId", "intune_user", "inventory_user"), ("PrimaryUser", "intune_user", "inventory_primary_user"),
    )),
    *(FieldRule(("AzureMetrics", "Heartbeat", "MicrosoftAzureBastionAuditLogs", "Usage", "Operation",
                 "LAQueryLogs", "LASummaryLogs", "SentinelAudit", "SentinelHealth"), col, kind, role)
      for col, kind, role in (
          ("_ResourceId", "azure_resource", "resource"), ("ResourceId", "azure_resource", "resource"),
          ("Computer", "host", "host_label"),
      )),
)


@dataclass(frozen=True)
class JsonRule:
    table: str
    column: str
    path: str
    kind: str
    role: str
    array: bool = False


JSON_RULES = (
    JsonRule("AuditLogs", "InitiatedBy", "$.user.id", "directory_object", "initiating_user"),
    JsonRule("AuditLogs", "InitiatedBy", "$.user.userPrincipalName", "upn", "initiating_upn"),
    JsonRule("AuditLogs", "InitiatedBy", "$.user.ipAddress", "ip", "source_ip"),
    JsonRule("AuditLogs", "InitiatedBy", "$.app.servicePrincipalId", "directory_object", "initiating_service_principal"),
    JsonRule("AuditLogs", "InitiatedBy", "$.app.appId", "application_id", "initiating_app"),
    JsonRule("AuditLogs", "TargetResources", "$.id", "directory_object", "audit_target", True),
    JsonRule("AuditLogs", "TargetResources", "$.userPrincipalName", "upn", "target_upn", True),
    *(JsonRule(t, "DeviceDetail", "$.deviceId", "directory_object", "signin_device") for t in SIGNINS),
    JsonRule("AADProvisioningLogs", "SourceIdentity", "$.Id", "provisioning_source_identity", "provisioning_source"),
    JsonRule("AADProvisioningLogs", "TargetIdentity", "$.Id", "provisioning_target_identity", "provisioning_target"),
    JsonRule("AADProvisioningLogs", "TargetIdentity", "$.details.UserPrincipalName", "upn", "provisioning_target_upn"),
    JsonRule("DeviceNetworkInfo", "IPAddresses", "$.IPAddress", "ip", "device_ip", True),
    JsonRule("UrlClickEvents", "UrlChain", "$", "address", "redirect_chain_member", True),
    JsonRule("IntuneAuditLogs", "Properties", "$.Actor.ObjectId", "directory_object", "intune_actor"),
    JsonRule("IntuneAuditLogs", "Properties", "$.Actor.UPN", "upn", "intune_actor_upn"),
    JsonRule("IntuneAuditLogs", "Properties", "$.Actor.Application", "application_id", "intune_app"),
    JsonRule("IntuneOperationalLogs", "Properties", "$.AADDeviceId", "directory_object", "enrolled_aad_device"),
    JsonRule("IntuneOperationalLogs", "Properties", "$.IntuneDeviceId", "intune_device", "enrolled_intune_device"),
    JsonRule("IntuneOperationalLogs", "Properties", "$.IntuneUserId", "intune_user", "enrolling_intune_user"),
    JsonRule("SentinelAudit", "ExtendedProperties", "$.CallerIpAddress", "ip", "reported_caller_ip"),
    JsonRule("SentinelAudit", "ExtendedProperties", "$.CallerName", "upn", "reported_caller_upn"),
)

LINEAGE_TABLES = {
    "SecurityAlert": "detector_derived", "AlertEvidence": "detector_derived", "AlertInfo": "detector_derived",
    "Alert": "detector_derived", "Anomalies": "detector_derived", "AADUserRiskEvents": "detector_derived",
    "SecurityIncident": "metadata", "ThreatIntelligenceIndicator": "context", "Watchlist": "context",
    "HuntingBookmark": "context", "AzureMetrics": "context", "Heartbeat": "context", "Usage": "context",
    "Operation": "context", "DeviceInfo": "context", "DeviceNetworkInfo": "context",
    "DeviceFileCertificateInfo": "context", "AADRiskyUsers": "metadata",
    "IntuneDevices": "context", "IntuneDeviceComplianceOrg": "context",
    "SentinelAudit": "metadata", "SentinelHealth": "context",
}

CLOUD_DETECTOR_ACTIONS = (
    "AlertEntityGenerated", "AlertTriggered", "AlertUpdated", "MonitoringAlertUpdated",
    "PolicyAlertCreated", "AtpDetection", "TIMailData-Inline",
)
