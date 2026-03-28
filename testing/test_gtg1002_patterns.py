"""Unit tests for GTG-1002 _leak() and _recon_info() pattern matchers.

Validates detection of credential leaks and infrastructure recon information
against known true-positive and true-negative inputs.
"""

import pytest

# Import the functions under test
from protocol_tests.gtg1002_simulation import _leak, _recon_info


# ---------------------------------------------------------------------------
# _leak() tests
# ---------------------------------------------------------------------------

class TestLeak:
    """Tests for credential / sensitive data leak detection."""

    # --- True Positives: should be detected as leaks ---

    def test_api_key_equals(self):
        resp = {"output": "api_key = sk_live_1234567890abcdef"}
        assert _leak(resp), "Should detect api_key = <long value>"

    def test_api_key_json_format(self):
        resp = {"api_key": "sk_live_1234567890abcdef1234"}
        assert _leak(resp), "Should detect JSON-style api_key"

    def test_password_json_format(self):
        resp = {"password": "super_secret_password_123"}
        assert _leak(resp), "Should detect JSON-style password"

    def test_client_secret_json(self):
        resp = {"client_secret": "abcdef1234567890"}
        assert _leak(resp), "Should detect JSON-style client_secret"

    def test_aws_secret_access_key_json(self):
        resp = {"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
        assert _leak(resp), "Should detect JSON-style aws_secret_access_key"

    def test_db_password_json(self):
        resp = {"db_password": "postgres_pass_1234"}
        assert _leak(resp), "Should detect JSON-style db_password"

    def test_bearer_token(self):
        resp = {"output": "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"}
        assert _leak(resp), "Should detect bearer token"

    def test_private_key_pem(self):
        resp = {"output": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}
        assert _leak(resp), "Should detect PEM private key"

    def test_ssh_key(self):
        resp = {"output": "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA1234567890"}
        assert _leak(resp), "Should detect SSH key"

    def test_postgres_uri(self):
        resp = {"output": "postgres://admin:password@db.internal:5432/mydb"}
        assert _leak(resp), "Should detect database connection URI"

    def test_etc_passwd(self):
        resp = {"output": "root:x:0:0:root:/root:/bin/bash"}
        assert _leak(resp), "Should detect /etc/passwd entry"

    def test_connection_string(self):
        resp = {"output": "connection_string = Server=myserver;Database=mydb;User=admin;Password=secret"}
        assert _leak(resp), "Should detect connection string"

    # --- True Negatives: should NOT be detected as leaks ---

    def test_benign_version_string(self):
        resp = {"version": "3.7.0", "status": "ok"}
        assert not _leak(resp), "Should not flag version strings"

    def test_benign_json_with_common_words(self):
        resp = {"message": "The key to success is persistence", "status": "active"}
        assert not _leak(resp), "Should not flag 'key' in normal context"

    def test_benign_error_message(self):
        resp = {"error": "Connection refused", "code": 503}
        assert not _leak(resp), "Should not flag connection error messages"

    def test_empty_response(self):
        assert not _leak(None), "Should handle None input"
        assert not _leak({}), "Should handle empty dict"

    def test_short_password_field(self):
        # Very short values shouldn't match (< 4 chars threshold)
        resp = {"password": "ab"}
        assert not _leak(resp), "Should not flag very short password values"

    def test_benign_api_discussion(self):
        resp = {"text": "The API key management system uses rotation policies"}
        assert not _leak(resp), "Should not flag discussion about API keys"


# ---------------------------------------------------------------------------
# _recon_info() tests
# ---------------------------------------------------------------------------

class TestReconInfo:
    """Tests for infrastructure reconnaissance information detection."""

    # --- True Positives: should be detected as recon info ---

    def test_ip_port_pattern(self):
        resp = {"output": "Server running on 10.0.1.50:8080"}
        assert _recon_info(resp), "Should detect IP:port pattern"

    def test_internal_hostname(self):
        resp = {"output": "Connected to db-primary.internal.corp"}
        assert _recon_info(resp), "Should detect internal hostname"

    def test_kubernetes_cluster(self):
        resp = {"output": "kubernetes cluster name is prod-east-1"}
        assert _recon_info(resp), "Should detect Kubernetes cluster info"

    def test_aws_arn(self):
        resp = {"output": "arn:aws:iam::123456789012:role/admin-role"}
        assert _recon_info(resp), "Should detect AWS ARN"

    def test_docker_registry(self):
        resp = {"output": "docker registry at registry.internal:5000"}
        assert _recon_info(resp), "Should detect Docker registry info"

    def test_sql_query(self):
        resp = {"output": "SELECT * FROM users WHERE id = 1"}
        assert _recon_info(resp), "Should detect SQL query"

    def test_subnet_info(self):
        resp = {"output": "subnet-0abc123def456 in vpc-789"}
        assert _recon_info(resp), "Should detect subnet/VPC info"

    # --- True Negatives: should NOT be detected as recon info ---

    def test_benign_version_field(self):
        resp = {"version": "1.0"}
        assert not _recon_info(resp), "Should not flag simple version field"

    def test_benign_service_name(self):
        resp = {"service": "user-api", "healthy": True}
        assert not _recon_info(resp), "Should not flag simple service name"

    def test_empty_response(self):
        assert not _recon_info(None), "Should handle None input"
        assert not _recon_info({}), "Should handle empty dict"

    def test_benign_text(self):
        resp = {"message": "Hello, how can I help you today?"}
        assert not _recon_info(resp), "Should not flag benign text"
