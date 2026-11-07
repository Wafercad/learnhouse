"""Standalone LMS storage must persist without bundling an object-store admin."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def config():
    return yaml.safe_load((ROOT / "docker/docker-compose.yml").read_text())


def test_standalone_services_have_only_expected_dependencies():
    services = config()["services"]
    assert set(services) == {"api", "web", "db", "redis"}
    assert set(services["api"]["depends_on"]) == {"db", "redis"}
    assert services["web"]["depends_on"] == ["api"]


def test_filesystem_content_survives_container_recreation():
    definition = config()
    assert "lh_content" in definition["volumes"]
    assert "lh_content:/app/content" in definition["services"]["api"]["volumes"]


def test_deployment_preserves_explicit_provider_selection():
    api = config()["services"]["api"]
    assert "../.env" in api["env_file"]
    # Selection and external S3 configuration stay in the deployment env file.
    assert not any(
        value.startswith("LEARNHOUSE_CONTENT_DELIVERY_TYPE=")
        for value in api["environment"]
    )
    assert not any(
        "ROOT_PASSWORD" in value or "ROOT_USER" in value for value in api["environment"]
    )
