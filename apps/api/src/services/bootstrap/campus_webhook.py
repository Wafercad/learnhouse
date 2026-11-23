"""The Academy's webhook endpoint for Wafercad Campus.

Campus projects course headers; this endpoint is how it hears of a publish,
rename or deletion at once instead of on its next periodic sweep. It is
bootstrap-owned because the endpoint is deployment wiring, not something an
author makes: a hand-made row is lost the first time the database moves.

Registered here, not through the webhooks API, because that API refuses every
private destination and Campus is a private sibling locally. The signing secret
is the one Campus is configured with, so neither side has to learn the other's.
"""

from datetime import datetime
from urllib.parse import urlparse
from uuid import uuid4

from sqlmodel import select

from src.db.webhooks import WebhookEndpoint
from src.services.utils.ssrf_guard import SSRFBlockedError, resolve_and_validate_url
from src.services.webhooks.crypto import decrypt_secret, encrypt_secret
from src.services.webhooks.dispatch import _allowed_private_hosts
from src.services.webhooks.events import WEBHOOK_EVENTS

from .protocol import Conflict, dependency, digest, result

_MIN_SECRET_LENGTH = 32


def execute(session, request):
    data = request["data"]
    if set(data) != {"foundation_step", "url", "events", "secret_env"}:
        raise Conflict("invalid_campus_webhook_spec")
    url, events = data["url"], sorted(set(data["events"]))
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise Conflict("invalid_campus_webhook_url")
    if not events or set(events) - set(WEBHOOK_EVENTS):
        raise Conflict("invalid_campus_webhook_events")
    secret = request.get("secrets", {}).get(data["secret_env"], "")
    if len(secret) < _MIN_SECRET_LENGTH:
        raise Conflict("campus_webhook_secret_required")
    foundation = dependency(request, "foundation_step")
    definition = digest({"url": url, "events": events})

    endpoint = session.exec(
        select(WebhookEndpoint).where(
            WebhookEndpoint.org_id == foundation["org_id"],
            WebhookEndpoint.url == url,
        )
    ).first()
    if endpoint:
        # Drift is for an operator to review, never to overwrite: a disabled
        # endpoint was disabled on purpose, and a different secret means one of
        # the two sides was rotated without the other.
        if not endpoint.is_active:
            raise Conflict("campus_webhook_disabled")
        if sorted(endpoint.events) != events:
            raise Conflict("campus_webhook_events_changed")
        if decrypt_secret(endpoint.secret_encrypted) != secret:
            raise Conflict("campus_webhook_secret_mismatch")
        receipt = dict(webhook_id=endpoint.id, webhook_uuid=endpoint.webhook_uuid)
        return result("ready", definition, receipt)
    # Missing is recreated even after an earlier receipt: unlike an organization
    # the endpoint holds no data, and losing it is exactly the failure this owns.
    if request["action"] == "verify":
        return result("missing", definition, {}, "campus_webhook_missing")
    try:
        # The check every delivery makes. Registering an endpoint LearnHouse will
        # then refuse to call is the silent failure this task exists to end.
        resolve_and_validate_url(url, allow_hosts=_allowed_private_hosts())
    except SSRFBlockedError:
        raise Conflict("campus_webhook_destination_refused")
    stamp = str(datetime.now())
    session.add(
        WebhookEndpoint(
            webhook_uuid=f"webhook_{uuid4()}",
            org_id=foundation["org_id"],
            url=url,
            secret_encrypted=encrypt_secret(secret),
            description="Wafercad Campus course projection",
            events=events,
            is_active=True,
            created_by_user_id=foundation["admin_id"],
            creation_date=stamp,
            update_date=stamp,
        )
    )
    session.flush()
    return execute(session, {**request, "action": "verify"})
