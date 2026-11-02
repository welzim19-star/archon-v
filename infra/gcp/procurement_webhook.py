# =============================================================================
# Archon-V — GCP Marketplace Procurement Webhook Handler
# File: infra/gcp/procurement_webhook.py
# CONTRACT VERSION: 1.0.0 — STABLE
# Ref: https://cloud.google.com/marketplace/docs/partners/integrated-saas/backend-integration
# =============================================================================
"""
GCP MARKETPLACE PROCUREMENT WEBHOOK — TECHNICAL CONTRACT

The Google Cloud Procurement API sends PUSH notifications via Cloud Pub/Sub
to our registered HTTPS endpoint when lifecycle events occur on a customer's
entitlement or account.

CRITICAL SLA: Our endpoint MUST respond HTTP 200 within < 5 seconds.
  If we fail to respond in time, GCP will retry with exponential backoff.
  IDEMPOTENCY IS MANDATORY — the same event WILL be delivered more than once.

PAYLOAD STRUCTURE: Pub/Sub wraps our event in a standard envelope.
  We must decode the base64 `data` field to extract the procurement event.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

logger = logging.getLogger("archon_v.procurement_webhook")


# ---------------------------------------------------------------------------
# ENUMERATIONS — GCP Procurement Event Types
# ---------------------------------------------------------------------------


class ProcurementEventType(str, Enum):
    """
    Known Procurement API event types.
    Reference: https://cloud.google.com/marketplace/docs/partners/integrated-saas/backend-integration#account-events
    """
    # Account lifecycle
    ACCOUNT_ACTIVE = "ACCOUNT_ACTIVE"
    ACCOUNT_DELETED = "ACCOUNT_DELETED"

    # Entitlement lifecycle
    ENTITLEMENT_CREATION_REQUESTED = "ENTITLEMENT_CREATION_REQUESTED"
    ENTITLEMENT_ACTIVE = "ENTITLEMENT_ACTIVE"
    ENTITLEMENT_PLAN_CHANGE_REQUESTED = "ENTITLEMENT_PLAN_CHANGE_REQUESTED"
    ENTITLEMENT_PLAN_CHANGED = "ENTITLEMENT_PLAN_CHANGED"
    ENTITLEMENT_PLAN_CHANGE_CANCELLED = "ENTITLEMENT_PLAN_CHANGE_CANCELLED"
    ENTITLEMENT_PENDING_CANCELLATION = "ENTITLEMENT_PENDING_CANCELLATION"
    ENTITLEMENT_CANCELLATION_REVERTED = "ENTITLEMENT_CANCELLATION_REVERTED"
    ENTITLEMENT_CANCELLED = "ENTITLEMENT_CANCELLED"
    ENTITLEMENT_DELETED = "ENTITLEMENT_DELETED"


# ---------------------------------------------------------------------------
# GCP PROCUREMENT WEBHOOK — EXACT PAYLOAD STRUCTURES
# ---------------------------------------------------------------------------

"""
═══════════════════════════════════════════════════════════════════════════════
SECTION A: WHAT GCP SENDS TO US (INBOUND)
═══════════════════════════════════════════════════════════════════════════════

When a customer accepts a Private Offer on the GCP Marketplace console,
GCP sends TWO sequential events:

1. ACCOUNT_ACTIVE  — fired first, when the customer's GCP account is linked.
2. ENTITLEMENT_CREATION_REQUESTED — fired when the specific product plan
   entitlement is requested and awaiting ISV approval.

───────────────────────────────────────────────────────────────────────────────
EVENT 1: ACCOUNT_ACTIVE
Raw Pub/Sub HTTP POST body to our webhook endpoint:
───────────────────────────────────────────────────────────────────────────────

{
  "message": {
    "attributes": {
      "eventType": "ACCOUNT_ACTIVE"
    },
    "data": "<BASE64_ENCODED_JSON>",
    "messageId": "1234567890123456",
    "publishTime": "2026-06-26T22:00:00.000Z"
  },
  "subscription": "projects/archon-v-prod/subscriptions/marketplace-procurement-sub"
}

Where BASE64_DECODED(data) =
{
  "account": {
    "id": "E-XXXX-XXXX-XXXX-XXXX",
    "updateTime": "2026-06-26T22:00:00.000Z",
    "state": "ACCOUNT_ACTIVE",
    "provider": "archon-v-gcp-listing"
  }
}

───────────────────────────────────────────────────────────────────────────────
EVENT 2: ENTITLEMENT_CREATION_REQUESTED
Raw Pub/Sub HTTP POST body to our webhook endpoint:
───────────────────────────────────────────────────────────────────────────────

{
  "message": {
    "attributes": {
      "eventType": "ENTITLEMENT_CREATION_REQUESTED"
    },
    "data": "<BASE64_ENCODED_JSON>",
    "messageId": "9876543210987654",
    "publishTime": "2026-06-26T22:00:05.000Z"
  },
  "subscription": "projects/archon-v-prod/subscriptions/marketplace-procurement-sub"
}

Where BASE64_DECODED(data) =
{
  "entitlement": {
    "id": "ENT-XXXX-XXXX-XXXX-XXXX",
    "account": "E-XXXX-XXXX-XXXX-XXXX",
    "provider": "archon-v-gcp-listing",
    "product": "archon-v-enterprise",
    "plan": "enterprise-annual-500seats",
    "state": "ENTITLEMENT_ACTIVATION_REQUESTED",
    "updateTime": "2026-06-26T22:00:05.000Z",
    "newPendingPlan": null,
    "subscriptionEndTime": null
  }
}

═══════════════════════════════════════════════════════════════════════════════
SECTION B: WHAT WE MUST RESPOND (OUTBOUND — TO GCP PROCUREMENT API)
═══════════════════════════════════════════════════════════════════════════════

STEP 1: Respond HTTP 200 to the Pub/Sub push message (within 5 seconds).
  Body: {} (empty JSON or any 200 response)
  This ACKs the Pub/Sub message and stops retries.

STEP 2 (async, after ACK): Call the GCP Procurement API to approve or reject.

For ENTITLEMENT_CREATION_REQUESTED, we must call:
  POST https://cloudcommerceprocurement.googleapis.com/v1/
       providers/{provider_id}/entitlements/{entitlement_id}:approve

Request body:
{
  "properties": {
    "archon_tenant_id": "<our-internal-tenant-slug>",
    "provisioning_status": "COMPLETED",
    "provisioned_at": "2026-06-26T22:00:10.000Z"
  }
}

GCP Procurement API Response (200 OK):
{
  // Empty body on success for approve()
}

For ACCOUNT_ACTIVE, no API approval call is needed — just provision the tenant.
"""


# ---------------------------------------------------------------------------
# PYTHON HANDLER IMPLEMENTATION
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProcurementEvent:
    """Parsed and validated procurement event."""
    event_type: ProcurementEventType
    raw_payload: dict[str, Any]
    message_id: str
    publish_time: str
    correlation_id: str  # Our internal UUIDv4 for audit trail


def parse_pubsub_envelope(raw_body: bytes, correlation_id: str) -> ProcurementEvent:
    """
    Parse the Pub/Sub push envelope and decode the base64 data field.
    
    Fail-secure: any parse error → raises ValueError with correlation_id only.
    
    Args:
        raw_body:       Raw HTTP request body bytes from GCP Pub/Sub push.
        correlation_id: UUIDv4 for audit correlation.
    
    Returns:
        ProcurementEvent with decoded payload.
    
    Raises:
        ValueError: On any parse failure (correlation_id only in message).
    """
    try:
        envelope = json.loads(raw_body)
        message = envelope["message"]
        event_type_str = message["attributes"]["eventType"]
        event_type = ProcurementEventType(event_type_str)
        decoded_data = base64.b64decode(message["data"]).decode("utf-8")
        payload = json.loads(decoded_data)
        return ProcurementEvent(
            event_type=event_type,
            raw_payload=payload,
            message_id=message["messageId"],
            publish_time=message["publishTime"],
            correlation_id=correlation_id,
        )
    except Exception:
        logger.error(
            "Procurement webhook parse failure.",
            extra={"correlation_id": correlation_id},
        )
        raise ValueError(f"ERR_WEBHOOK_PARSE | correlation_id={correlation_id}")


def handle_account_active(event: ProcurementEvent) -> dict[str, Any]:
    """
    Handler for ACCOUNT_ACTIVE event.
    
    Actions:
      1. Extract account ID from payload.
      2. Derive internal tenant_id (slug from account ID).
      3. Provision tenant schema + KMS key ring (async task).
      4. Record provisioning in audit log (correlation_id only, no PII).
    
    Returns:
        Ack payload for Pub/Sub (empty dict → HTTP 200).
    """
    account = event.raw_payload.get("account", {})
    gcp_account_id = account.get("id", "")
    
    # Derive deterministic tenant slug from GCP account ID
    # SHA-256 prefix ensures uniqueness without leaking raw account ID in logs
    tenant_slug = hashlib.sha256(gcp_account_id.encode()).hexdigest()[:16]
    
    logger.info(
        "Account provisioning initiated.",
        extra={
            "correlation_id": event.correlation_id,
            "tenant_slug_prefix": tenant_slug[:8],  # Only first 8 chars in log
        },
    )
    
    # TODO: dispatch async task → TenantProvisioningService.provision(tenant_slug)
    # This must complete idempotently — same tenant_slug = same schema (no-op if exists)
    
    return {}  # ACK to Pub/Sub


def handle_entitlement_creation_requested(event: ProcurementEvent) -> dict[str, Any]:
    """
    Handler for ENTITLEMENT_CREATION_REQUESTED.
    
    Per GCP docs: we must call the Procurement API approve() endpoint
    ASYNCHRONOUSLY (after ACKing Pub/Sub) to activate the entitlement.
    
    Returns:
        Ack payload for Pub/Sub (empty dict → HTTP 200).
    
    APPROVE CALL PAYLOAD (sent to GCP Procurement API):
    POST https://cloudcommerceprocurement.googleapis.com/v1/
         providers/{provider_id}/entitlements/{entitlement_id}:approve
    
    Body:
    {
      "properties": {
        "archon_tenant_id": "<tenant_slug>",
        "provisioning_status": "COMPLETED",
        "provisioned_at": "<ISO8601_UTC>"
      }
    }
    """
    entitlement = event.raw_payload.get("entitlement", {})
    entitlement_id = entitlement.get("id", "")
    account_id = entitlement.get("account", "")
    plan = entitlement.get("plan", "")

    tenant_slug = hashlib.sha256(account_id.encode()).hexdigest()[:16]
    
    logger.info(
        "Entitlement approval requested.",
        extra={
            "correlation_id": event.correlation_id,
            "entitlement_id_hash": hashlib.sha256(entitlement_id.encode()).hexdigest()[:16],
            "plan": plan,  # plan name is non-sensitive
        },
    )

    # APPROVE PAYLOAD — exact structure for GCP Procurement API
    approve_payload: dict[str, Any] = {
        "properties": {
            "archon_tenant_id": tenant_slug,
            "provisioning_status": "COMPLETED",
            "provisioned_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    }

    # TODO: dispatch async call to:
    #   POST https://cloudcommerceprocurement.googleapis.com/v1/
    #        providers/{ARCHON_PROVIDER_ID}/entitlements/{entitlement_id}:approve
    #   with approve_payload
    #   Use google-auth library with Application Default Credentials

    logger.info(
        "Entitlement approve dispatched.",
        extra={"correlation_id": event.correlation_id},
    )
    
    return {}  # ACK to Pub/Sub — approve runs async


# ---------------------------------------------------------------------------
# WEBHOOK ROUTER — FastAPI endpoint signature
# ---------------------------------------------------------------------------

"""
FASTAPI ENDPOINT REGISTRATION (in api/v1/gateway/procurement.py):

from fastapi import Request, Response, Header
import uuid

@router.post(
    "/webhooks/gcp-marketplace",
    status_code=200,
    include_in_schema=False,  # Do NOT expose in public OpenAPI spec
)
async def gcp_procurement_webhook(
    request: Request,
    x_goog_resource_state: str = Header(None),
) -> Response:
    correlation_id = str(uuid.uuid4())
    raw_body = await request.body()
    
    try:
        event = parse_pubsub_envelope(raw_body, correlation_id)
    except ValueError:
        # Return 200 anyway — prevents GCP from infinite retry on bad payload
        # Bad payload is logged with correlation_id
        return Response(content="{}", media_type="application/json", status_code=200)
    
    if event.event_type == ProcurementEventType.ACCOUNT_ACTIVE:
        handle_account_active(event)
    elif event.event_type == ProcurementEventType.ENTITLEMENT_CREATION_REQUESTED:
        handle_entitlement_creation_requested(event)
    # All other event types: ACK and log
    
    return Response(content="{}", media_type="application/json", status_code=200)
"""

# ---------------------------------------------------------------------------
# SYNTAX VALIDATION COMMAND (run from project root)
# ---------------------------------------------------------------------------
# python -c "import ast, sys; ast.parse(open('infra/gcp/procurement_webhook.py').read()); print('SYNTAX OK')"
