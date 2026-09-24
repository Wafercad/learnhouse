"""Explicit LAN/VPN aliases: preserve issuer trust and exact callback binding."""

from urllib.parse import urlsplit, urlunsplit
from config.oidc import OIDCConfig


def origin(value: str) -> str:
    url = urlsplit(value)
    if (url.scheme not in {"http", "https"} or not url.netloc or url.username
            or url.password or url.query or url.fragment or url.path not in {"", "/"}):
        raise ValueError("Invalid configured frontend origin")
    return urlunsplit((url.scheme, url.netloc, "", "", ""))


def frontend_route(cfg: OIDCConfig, frontend_origin: str | None) -> tuple[str, str | None]:
    if not frontend_origin:
        return cfg.redirect_uri, None
    academy = origin(frontend_origin)
    console = cfg.frontend_origins.get(academy)
    if console is None:
        # Without aliases, retain the single configured callback origin.
        expected = urlsplit(cfg.redirect_uri)
        if not cfg.frontend_origins and academy == f"{expected.scheme}://{expected.netloc}":
            return cfg.redirect_uri, None
        raise ValueError("This frontend origin is not configured for sign-in")
    return academy + "/auth/sso/callback", origin(console) + "/oauth/authorize"


def callback_config(cfg: OIDCConfig, callback: str | None) -> OIDCConfig:
    allowed = {cfg.redirect_uri} | {
        origin(value) + "/auth/sso/callback" for value in cfg.frontend_origins
    }
    if callback is not None and callback not in allowed:
        raise ValueError("The saved sign-in callback is no longer allowed")
    return cfg.model_copy(update={"redirect_uri": callback or cfg.redirect_uri})


def transport_document(cfg: OIDCConfig, document: dict) -> dict:
    if document.get("issuer") != cfg.issuer:
        raise ValueError("The identity provider issuer does not match configuration")
    if not cfg.endpoint_base:
        return document
    canonical = cfg.issuer.rstrip("/") + "/"
    mapped = dict(document)
    for key in ("token_endpoint", "jwks_uri"):
        endpoint = document.get(key)
        if not isinstance(endpoint, str) or not endpoint.startswith(canonical):
            raise ValueError("The provider endpoint is outside the configured issuer")
        mapped[key] = cfg.endpoint_base.rstrip("/") + "/" + endpoint[len(canonical):]
    return mapped
