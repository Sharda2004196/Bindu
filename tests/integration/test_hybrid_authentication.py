"""Integration tests for hybrid OAuth2 + DID authentication."""

import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

from bindu.server.middleware.auth.hydra import HydraMiddleware
from bindu.utils.did_signature import sign_request


@pytest.fixture
def mock_did_extension():
    """Create a mock DID extension."""
    mock_ext = MagicMock()
    mock_ext.did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"  # pragma: allowlist secret
    mock_ext.public_key_base58 = (
        "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"  # pragma: allowlist secret
    )
    mock_ext.sign_message.return_value = "mock_signature_abc123"
    return mock_ext


@pytest.fixture
def mock_hydra_config():
    """Create mock Hydra configuration."""
    config = MagicMock()
    config.admin_url = "https://hydra-admin.example.com"
    config.public_url = "https://hydra.example.com"
    config.timeout = 10
    config.verify_ssl = True
    config.public_endpoints = ["/docs", "/.well-known/*"]
    return config


@pytest.fixture
def mock_request():
    """Create a mock Starlette request."""
    request = MagicMock(spec=Request)
    request.url.path = "/api/test"
    request.headers = {}
    request.body = AsyncMock(return_value=b'{"test": "data"}')
    request.state = MagicMock()
    return request


class TestHybridAuthenticationFlow:
    """Test complete hybrid authentication flow."""

    @pytest.mark.asyncio
    async def test_successful_hybrid_authentication(
        self, mock_hydra_config, mock_request, mock_did_extension
    ):
        """Test successful authentication with both token and DID signature."""
        # Setup
        middleware = HydraMiddleware(app=MagicMock(), auth_config=mock_hydra_config)

        # Mock token validation
        token_payload = {
            "active": True,
            "sub": "test-user",
            "client_id": mock_did_extension.did,
            "scope": "agent:read agent:write",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "token_type": "access_token",
            "grant_type": "client_credentials",
        }

        with patch.object(middleware, "_validate_token", return_value=token_payload):
            with patch.object(
                middleware.hydra_client,
                "get_oauth_client",
                return_value={
                    "client_id": mock_did_extension.did,
                    "metadata": {
                        "public_key": mock_did_extension.public_key_base58,
                        "hybrid_auth": True,
                    },
                },
            ):
                # Create signed request
                body = {"test": "data"}
                signature_headers = sign_request(
                    body, mock_did_extension.did, mock_did_extension
                )

                mock_request.headers = {
                    "Authorization": "Bearer test_token",
                    **signature_headers,
                }

                # Mock signature verification to return True
                with patch("base58.b58decode") as mock_b58:
                    mock_b58.return_value = b"fake_decoded_bytes"
                    with patch("nacl.signing.VerifyKey") as mock_verify_key:
                        mock_verify_key.return_value.verify.return_value = None
                        # Execute
                        call_next = AsyncMock(
                            return_value=JSONResponse({"success": True})
                        )
                        response = await middleware.dispatch(mock_request, call_next)

                    # Verify
                    assert response.status_code == 200
                    assert mock_request.state.authenticated is True
                    assert (
                        mock_request.state.user["client_id"] == mock_did_extension.did
                    )
                    assert "signature_info" in mock_request.state.user
                    assert (
                        mock_request.state.user["signature_info"]["did_verified"]
                        is True
                    )

    @pytest.mark.asyncio
    async def test_authentication_with_invalid_signature(
        self, mock_hydra_config, mock_request, mock_did_extension
    ):
        """Test that invalid DID signature is rejected."""
        middleware = HydraMiddleware(app=MagicMock(), auth_config=mock_hydra_config)

        token_payload = {
            "active": True,
            "sub": "test-user",
            "client_id": mock_did_extension.did,
            "scope": "agent:read",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "token_type": "access_token",
            "grant_type": "client_credentials",
        }

        with patch.object(middleware, "_validate_token", return_value=token_payload):
            with patch.object(
                middleware.hydra_client,
                "get_oauth_client",
                return_value={
                    "client_id": mock_did_extension.did,
                    "metadata": {
                        "public_key": mock_did_extension.public_key_base58,
                    },
                },
            ):
                # Create request with invalid signature
                signature_headers = sign_request(
                    {"test": "data"}, mock_did_extension.did, mock_did_extension
                )

                mock_request.headers = {
                    "Authorization": "Bearer test_token",
                    **signature_headers,
                }

                # Mock signature verification to raise BadSignatureError
                from nacl.exceptions import BadSignatureError

                with patch("base58.b58decode") as mock_b58:
                    mock_b58.return_value = b"fake_decoded_bytes"
                    with patch("nacl.signing.VerifyKey") as mock_verify_key:
                        mock_verify_key.return_value.verify.side_effect = (
                            BadSignatureError("Invalid")
                        )
                        call_next = AsyncMock()
                        response = await middleware.dispatch(mock_request, call_next)

                    # Verify rejection
                    assert response.status_code == 403
                    call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_authentication_without_signature_backward_compatible(
        self, mock_hydra_config, mock_request
    ):
        """Test that requests without DID signature still work (backward compatibility)."""
        middleware = HydraMiddleware(app=MagicMock(), auth_config=mock_hydra_config)

        # Non-DID client
        token_payload = {
            "active": True,
            "sub": "test-user",
            "client_id": "agent-legacy-client",
            "scope": "agent:read",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "token_type": "access_token",
            "grant_type": "client_credentials",
        }

        with patch.object(middleware, "_validate_token", return_value=token_payload):
            mock_request.headers = {
                "Authorization": "Bearer test_token",
            }

            call_next = AsyncMock(return_value=JSONResponse({"success": True}))
            response = await middleware.dispatch(mock_request, call_next)

            # Should succeed without DID verification
            assert response.status_code == 200
            assert mock_request.state.authenticated is True

    @pytest.mark.asyncio
    async def test_authentication_with_expired_timestamp(
        self, mock_hydra_config, mock_request, mock_did_extension
    ):
        """Test that expired timestamps are rejected."""
        middleware = HydraMiddleware(app=MagicMock(), auth_config=mock_hydra_config)

        token_payload = {
            "active": True,
            "sub": "test-user",
            "client_id": mock_did_extension.did,
            "scope": "agent:read",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "token_type": "access_token",
            "grant_type": "client_credentials",
        }

        with patch.object(middleware, "_validate_token", return_value=token_payload):
            with patch.object(
                middleware.hydra_client,
                "get_oauth_client",
                return_value={
                    "client_id": mock_did_extension.did,
                    "metadata": {
                        "public_key": mock_did_extension.public_key_base58,
                    },
                },
            ):
                # Create request with old timestamp
                old_timestamp = int(time.time()) - 600  # 10 minutes ago
                signature_headers = sign_request(
                    {"test": "data"},
                    mock_did_extension.did,
                    mock_did_extension,
                    timestamp=old_timestamp,
                )

                mock_request.headers = {
                    "Authorization": "Bearer test_token",
                    **signature_headers,
                }

                call_next = AsyncMock()
                response = await middleware.dispatch(mock_request, call_next)

                # Should be rejected due to expired timestamp
                assert response.status_code == 403
                call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_authentication_with_did_mismatch(
        self, mock_hydra_config, mock_request, mock_did_extension
    ):
        """Test that DID mismatch between token and header is rejected."""
        middleware = HydraMiddleware(app=MagicMock(), auth_config=mock_hydra_config)

        token_payload = {
            "active": True,
            "sub": "test-user",
            "client_id": mock_did_extension.did,
            "scope": "agent:read",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "token_type": "access_token",
            "grant_type": "client_credentials",
        }

        with patch.object(middleware, "_validate_token", return_value=token_payload):
            # Create request with different DID in header
            different_did = "did:key:z6MkDifferentDID"
            signature_headers = sign_request(
                {"test": "data"}, different_did, mock_did_extension
            )

            mock_request.headers = {
                "Authorization": "Bearer test_token",
                **signature_headers,
            }

            call_next = AsyncMock()
            response = await middleware.dispatch(mock_request, call_next)

            # Should be rejected due to DID mismatch
            assert response.status_code == 403
            call_next.assert_not_called()


class TestHybridAuthClient:
    """Test hybrid auth client utilities."""

    def test_hybrid_auth_client_initialization(self, mock_did_extension):
        """Test initializing hybrid auth client."""
        from bindu.utils.hybrid_auth_client import HybridAuthClient

        client = HybridAuthClient(
            agent_id="test-agent",
            credentials_dir=Path("/tmp/.bindu"),
            did_extension=mock_did_extension,
        )

        assert client.agent_id == "test-agent"
        assert client.credentials_dir == Path("/tmp/.bindu")
        assert client.did_extension == mock_did_extension
