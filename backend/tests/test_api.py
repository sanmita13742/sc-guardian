import json

from fastapi.testclient import TestClient

from app import main


client = TestClient(main.app)


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_invalid_url_rejected_without_starting_job():
    response = client.post("/api/analyses", json={"repository_url": "https://example.com/a/b"})
    assert response.status_code == 422


def test_fixture_graph_and_artifact_allowlist(tmp_path, monkeypatch):
    job_id = "c" * 32
    run_dir = tmp_path / job_id
    run_dir.mkdir()
    graph = {"format": "nodegoat-guardian-graph-v1", "root": "r", "nodes": [], "edges": [], "stats": {}, "info": {}}
    (run_dir / "graph.json").write_text(json.dumps(graph), encoding="utf-8")
    (run_dir / "report.md").write_text("# report", encoding="utf-8")
    monkeypatch.setattr(main, "RUNS_DIR", tmp_path.resolve())
    response = client.get(f"/api/analyses/{job_id}/graph")
    assert response.status_code == 200
    assert response.json()["format"] == "nodegoat-guardian-graph-v1"
    assert client.get(f"/api/analyses/{job_id}/artifacts/graph.json").status_code == 200
    assert client.get(f"/api/analyses/{job_id}/artifacts/report.md").status_code == 200
    assert client.get(f"/api/analyses/{job_id}/artifacts/secrets.txt").status_code == 404
    assert client.get(f"/api/analyses/{job_id}/artifacts/..%2Fmanifest.json").status_code in {404, 422}
