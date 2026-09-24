"""Aliases cannot change the trusted issuer or substitute an OAuth callback."""
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import pytest

from src.services.auth import oidc
from src.services.auth.oidc_transport import callback_config, frontend_route, transport_document
from src.tests.services.test_sso_oidc import _cfg, _DISCOVERY


def config():
    return _cfg().model_copy(update={
        "endpoint_base": "http://account:8001/account/api/v1",
        "frontend_origins": {"http://192.168.1.34:3000": "http://192.168.1.34:4300"},
    })


def test_transport_maps_backchannel_without_changing_issuer():
    result = transport_document(config(), _DISCOVERY)
    assert result['issuer'] == 'https://idp.test'
    assert result['token_endpoint'] == 'http://account:8001/account/api/v1/oauth/token'
    assert result['jwks_uri'] == 'http://account:8001/account/api/v1/oauth/jwks'


@pytest.mark.parametrize('change', [
    {'issuer': 'https://evil.test'}, {'token_endpoint': 'https://evil.test/token'},
    {'jwks_uri': 'https://idp.test.evil.test/keys'},
])
def test_rejects_foreign_issuer_and_endpoints(change):
    with pytest.raises(ValueError):
        transport_document(config(), {**_DISCOVERY, **change})


@pytest.mark.parametrize('origin', ['http://evil.test', 'http://192.168.1.34:3000/evil', '//evil.test'])
def test_rejects_unregistered_frontend(origin):
    with pytest.raises(ValueError):
        frontend_route(config(), origin)


def test_saved_callback_must_still_be_registered():
    cfg = config()
    callback, authorize = frontend_route(cfg, 'http://192.168.1.34:3000')
    assert authorize == 'http://192.168.1.34:4300/oauth/authorize'
    assert callback_config(cfg, callback).redirect_uri == callback
    with pytest.raises(ValueError):
        callback_config(cfg, 'https://evil.test/auth/sso/callback')


@pytest.mark.asyncio
async def test_alias_callback_is_bound_to_server_side_state(monkeypatch):
    monkeypatch.setattr(oidc, 'get_redis_client', lambda: None)
    monkeypatch.setattr(oidc, '_discover', AsyncMock(return_value=_DISCOVERY))
    url, state = await oidc.build_authorization_url(config(), 'academy', '/courses', 'http://192.168.1.34:3000')
    parsed = urlsplit(url)
    assert parsed.netloc == '192.168.1.34:4300'
    callback = parse_qs(parsed.query)['redirect_uri'][0]
    assert callback == 'http://192.168.1.34:3000/auth/sso/callback'
    assert oidc._pop_state(state)['redirect_uri'] == callback
