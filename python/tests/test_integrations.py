"""Integration client tests — mock external APIs, verify request shapes."""
from __future__ import annotations

import os
from unittest.mock import patch, MagicMock

import pytest


class TestOktaClient:
    def test_init_requires_env_vars(self):
        from integrations.okta.okta_client import OktaClient
        with patch.dict(os.environ, {"OKTA_ORG_URL": "", "OKTA_API_TOKEN": ""}, clear=True):
            with pytest.raises(RuntimeError):
                OktaClient()

    def test_session_has_retry_adapter(self):
        from integrations.okta.okta_client import OktaClient
        with patch.dict(os.environ, {
            "OKTA_ORG_URL": "https://dev-test.okta.com",
            "OKTA_API_TOKEN": "fake_token",
        }):
            client = OktaClient()
        # urllib3 Retry adapter is mounted for https://
        adapter = client.session.adapters["https://"]
        assert adapter.max_retries.total == 3

    def test_lookup_user_id_uses_get(self):
        from integrations.okta.okta_client import OktaClient
        with patch.dict(os.environ, {
            "OKTA_ORG_URL": "https://dev-test.okta.com",
            "OKTA_API_TOKEN": "fake_token",
        }):
            client = OktaClient()
        with patch.object(client.session, "get") as mock_get:
            mock_get.return_value.json.return_value = {"id": "00u123"}
            mock_get.return_value.raise_for_status = MagicMock()
            uid = client._lookup_user_id("user@test.local")
        assert uid == "00u123"
        mock_get.assert_called_once()


class TestCrowdStrikeClient:
    def test_init_requires_env_vars(self):
        from integrations.crowdstrike.falcon_client import FalconClient
        with patch.dict(os.environ, {"CROWDSTRIKE_CLIENT_ID": "", "CROWDSTRIKE_CLIENT_SECRET": ""}, clear=True):
            with pytest.raises(RuntimeError):
                FalconClient()


class TestIntuneClient:
    def test_init_requires_all_env_vars(self):
        from integrations.intune.graph_client import GraphClient
        with patch.dict(os.environ, {
            "INTUNE_TENANT_ID": "tenant",
            "INTUNE_CLIENT_ID": "",
            "INTUNE_CLIENT_SECRET": "",
        }, clear=True):
            with pytest.raises(RuntimeError):
                GraphClient()

    def test_token_caching(self):
        from integrations.intune.graph_client import GraphClient
        with patch.dict(os.environ, {
            "INTUNE_TENANT_ID": "tenant",
            "INTUNE_CLIENT_ID": "client",
            "INTUNE_CLIENT_SECRET": "secret",
        }):
            client = GraphClient()
        # Pre-populate token
        client._token = "fake_token"
        client._token_expires = 9_999_999_999.0
        # Should return cached token without HTTP call
        with patch("requests.post") as mock_post:
            token = client._get_token()
        assert token == "fake_token"
        mock_post.assert_not_called()


class TestWazuhClient:
    def test_requires_password(self):
        from integrations.wazuh_client import WazuhClient
        with patch.dict(os.environ, {"WAZUH_API_PASSWORD": ""}, clear=True):
            with pytest.raises(RuntimeError):
                WazuhClient()
