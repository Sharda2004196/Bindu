"""Integration tests for Hydra authentication flow."""

import pytest
from unittest.mock import AsyncMock, patch

from bindu.auth.hydra_client import HydraClient
from bindu.auth.hydra_registration import (
    register_agent_in_hydra,
    load_agent_credentials,
)
from bindu.utils.token_utils import get_client_credentials_token
from pathlib import Path
import tempfile


@pytest.mark.asyncio
async def test_hydra_client_health_check():
    """Test Hydra client health check."""
    # This test requires actual Hydra instance running
    # Skip if Hydra is not available
    pytest.skip("Requires running Hydra instance")

    async with HydraClient(
        admin_url="https://hydra-admin.getbindu.com",
        verify_ssl=True,
    ) as hydra:
        is_healthy = await hydra.health_check()
        assert is_healthy is True


@pytest.mark.asyncio
async def test_oauth_client_lifecycle():
    """Test OAuth client creation, retrieval, and deletion."""
    pytest.skip("Requires running Hydra instance")

    client_data = {
        "client_id": "test-client-123",
        "client_secret": "test-secret-456",
        "client_name": "Test Client",
        "grant_types": ["client_credentials"],
        "scope": "agent:read agent:write",
        "token_endpoint_auth_method": "client_secret_basic",
    }

    async with HydraClient(
        admin_url="https://hydra-admin.getbindu.com",
        verify_ssl=True,
    ) as hydra:
        # Create client
        created = await hydra.create_oauth_client(client_data)
        assert created["client_id"] == "test-client-123"

        # Get client
        retrieved = await hydra.get_oauth_client("test-client-123")
        assert retrieved is not None
        assert retrieved["client_name"] == "Test Client"

        # Delete client
        deleted = await hydra.delete_oauth_client("test-client-123")
        assert deleted is True

        # Verify deletion
        retrieved_after = await hydra.get_oauth_client("test-client-123")
        assert retrieved_after is None


@pytest.mark.asyncio
async def test_token_introspection():
    """Test token introspection."""
    pytest.skip("Requires running Hydra instance and valid token")

    token = "valid_access_token_here"

    async with HydraClient(
        admin_url="https://hydra-admin.getbindu.com",
        verify_ssl=True,
    ) as hydra:
        result = await hydra.introspect_token(token)
        assert result["active"] is True
        assert "sub" in result
        assert "exp" in result


@pytest.mark.asyncio
async def test_agent_registration_flow():
    """Test complete agent registration flow."""
    with tempfile.TemporaryDirectory() as tmpdir:
        credentials_dir = Path(tmpdir)

        # Mock Hydra client - DID is used as client_id
        test_did = "did:key:test123"
        mock_client = {
            "client_id": test_did,
            "client_name": "Test Agent",
            "grant_types": ["client_credentials"],
        }

        with patch("bindu.auth.hydra_registration.HydraClient") as MockHydraClient:
            mock_hydra = AsyncMock()
            mock_hydra.__aenter__.return_value = mock_hydra
            mock_hydra.__aexit__.return_value = None
            mock_hydra.get_oauth_client.return_value = None
            mock_hydra.create_oauth_client.return_value = mock_client
            MockHydraClient.return_value = mock_hydra

            # Register agent
            credentials = await register_agent_in_hydra(
                agent_id="test-123",
                agent_name="Test Agent",
                agent_url="http://localhost:3773",
                did=test_did,
                credentials_dir=credentials_dir,
            )

            assert credentials is not None
            assert credentials.agent_id == "test-123"
            assert credentials.client_id == test_did

            # Verify credentials were saved (lookup by DID, not agent_id)
            loaded = load_agent_credentials(test_did, credentials_dir)
            assert loaded is not None
            assert loaded.client_id == credentials.client_id


@pytest.mark.asyncio
async def test_client_credentials_token_flow():
    """Test getting token with client credentials."""
    pytest.skip("Requires running Hydra instance")

    # Use test client credentials
    client_id = "test-client"
    client_secret = "test-secret"

    token_response = await get_client_credentials_token(
        client_id=client_id,
        client_secret=client_secret,
        scope="agent:read agent:write",
    )

    assert token_response is not None
    assert "access_token" in token_response
    assert "token_type" in token_response
    assert token_response["token_type"] == "bearer"
    assert "expires_in" in token_response


@pytest.mark.asyncio
async def test_invalid_credentials_returns_none():
    """Test that invalid credentials return None."""
    pytest.skip("Requires running Hydra instance")

    token_response = await get_client_credentials_token(
        client_id="invalid-client",
        client_secret="invalid-secret",
        scope="agent:read",
    )

    assert token_response is None


@pytest.mark.asyncio
async def test_token_revocation():
    """Test token revocation."""
    pytest.skip("Requires running Hydra instance and valid token")

    from bindu.utils.token_utils import revoke_token

    # Get a token first
    token_response = await get_client_credentials_token(
        client_id="test-client",
        client_secret="test-secret",
    )

    token = token_response["access_token"]

    # Revoke it
    revoked = await revoke_token(token)
    assert revoked is True

    # Verify it's revoked by introspecting
    async with HydraClient(
        admin_url="https://hydra-admin.getbindu.com",
        verify_ssl=True,
    ) as hydra:
        result = await hydra.introspect_token(token)
        assert result["active"] is False
