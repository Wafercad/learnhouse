"""OIDC configuration and explicit deployment transport aliases."""
import json
import os
from pydantic import BaseModel, Field

class OIDCConfig(BaseModel):
    """Generic OIDC Relying-Party settings (LearnHouse federates to an external
    IdP — Wafercad's account_service). Auto-enabled when issuer + client_id +
    redirect_uri are all set, mirroring the Judge0/Tinybird pattern."""

    issuer: str  # IdP base URL; serves /.well-known/openid-configuration
    client_id: str
    client_secret: str | None  # None => public client (PKCE only)
    redirect_uri: str  # this fork's frontend callback, registered with the IdP
    scopes: str  # space-delimited; default "openid email profile"
    default_role_id: int  # role a JIT user gets in the target org
    provider: str  # label returned by /auth/sso/check (e.g. "custom_oidc")
    endpoint_base: str | None = None
    frontend_origins: dict[str, str] = Field(default_factory=dict)

def load_oidc_config(yaml_config: dict) -> OIDCConfig | None:
    oidc_yaml = yaml_config.get("oidc_config", {}) or {}
    oidc_issuer = os.environ.get("LEARNHOUSE_OIDC_ISSUER") or oidc_yaml.get("issuer", "")
    oidc_client_id = os.environ.get("LEARNHOUSE_OIDC_CLIENT_ID") or oidc_yaml.get("client_id", "")
    oidc_client_secret = os.environ.get("LEARNHOUSE_OIDC_CLIENT_SECRET") or oidc_yaml.get("client_secret")
    oidc_redirect_uri = os.environ.get("LEARNHOUSE_OIDC_REDIRECT_URI") or oidc_yaml.get("redirect_uri", "")
    oidc_scopes = os.environ.get("LEARNHOUSE_OIDC_SCOPES") or oidc_yaml.get("scopes", "openid email profile")
    oidc_default_role_id = os.environ.get("LEARNHOUSE_OIDC_DEFAULT_ROLE_ID") or oidc_yaml.get("default_role_id")
    oidc_provider = os.environ.get("LEARNHOUSE_OIDC_PROVIDER") or oidc_yaml.get("provider", "custom_oidc")

    oidc_config = None
    if oidc_issuer and oidc_client_id and oidc_redirect_uri:
        oidc_config = OIDCConfig(
            issuer=oidc_issuer.rstrip("/"),
            client_id=oidc_client_id,
            client_secret=oidc_client_secret or None,
            redirect_uri=oidc_redirect_uri,
            scopes=oidc_scopes,
            default_role_id=int(oidc_default_role_id) if oidc_default_role_id else 4,
            provider=oidc_provider,
            endpoint_base=os.environ.get("LEARNHOUSE_OIDC_ENDPOINT_BASE") or None,
            frontend_origins=json.loads(os.environ.get("LEARNHOUSE_OIDC_FRONTEND_ORIGINS", "{}")),
        )

    return oidc_config
