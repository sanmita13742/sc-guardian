import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_api_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_api_repositories():
    response = client.get("/api/repositories")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["repository"] == "nodegoat"


def test_api_dependencies():
    response = client.get("/api/dependencies/nodegoat")
    assert response.status_code == 200
    data = response.json()
    assert data["total_components"] == 1091
    assert data["direct_dependencies"] == 36
    assert data["transitive_dependencies"] == 1055


def test_api_graph():
    response = client.get("/api/graph/nodegoat")
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["total_nodes"] == 1092
    assert data["summary"]["total_edges"] > 1000


def test_api_sbom():
    response = client.get("/api/sbom/nodegoat?format=comparison")
    assert response.status_code == 200
    data = response.json()
    assert data["total_sbom_components"] > 0
    assert data["validation_status"].startswith("valid")
