from __future__ import annotations

import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .models import AnalysisRequest, AnalysisStatus
from .pipeline import ARTIFACTS, STAGES, AnalysisPipeline, PipelineError, utc_now, validate_repository_url


WORKSPACE = Path(os.getenv("GUARDIAN_WORKSPACE", Path(__file__).resolve().parents[2])).resolve()
RUNS_DIR = (WORKSPACE / "analysis_runs").resolve()
RUNS_DIR.mkdir(parents=True, exist_ok=True)
MAX_JOBS = max(1, min(4, int(os.getenv("GUARDIAN_MAX_JOBS", "1"))))


class JobManager:
    def __init__(self, pipeline: AnalysisPipeline):
        self.pipeline = pipeline
        self.jobs: dict[str, dict[str, Any]] = {}
        self.cancel_events: dict[str, threading.Event] = {}
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=MAX_JOBS, thread_name_prefix="guardian-analysis")
        self._load_manifests()

    def _load_manifests(self) -> None:
        for path in RUNS_DIR.glob("*/manifest.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if data.get("job_id") == path.parent.name:
                    self.jobs[path.parent.name] = data
            except (OSError, json.JSONDecodeError):
                continue

    def create(self, repository_url: str) -> dict[str, Any]:
        canonical_url = validate_repository_url(repository_url)
        job_id = uuid.uuid4().hex
        job = {
            "job_id": job_id,
            "status": "queued",
            "stage": "queued",
            "stage_label": STAGES["queued"][0],
            "progress": 0,
            "repository_url": canonical_url,
            "created_at": utc_now(),
            "started_at": None,
            "completed_at": None,
            "commit_sha": None,
            "error": None,
            "summary": None,
        }
        event = threading.Event()
        with self.lock:
            self.jobs[job_id] = job
            self.cancel_events[job_id] = event
        self.executor.submit(self._run, job_id, event)
        return self.public(job)

    def _update(self, job_id: str, stage_id: str, values: dict[str, Any]) -> None:
        with self.lock:
            job = self.jobs[job_id]
            job.update(values)
            job["stage"] = stage_id

    def _run(self, job_id: str, event: threading.Event) -> None:
        with self.lock:
            job = self.jobs[job_id]
            job["status"] = "running"
            job["started_at"] = utc_now()
            manifest = dict(job)
        try:
            completed = self.pipeline.execute(manifest, lambda stage, values: self._update(job_id, stage, values), event)
            with self.lock:
                self.jobs[job_id].update(completed)
        except PipelineError as exc:
            cancelled = exc.code == "CANCELLED"
            with self.lock:
                job = self.jobs[job_id]
                job.update(
                    {
                        "status": "cancelled" if cancelled else "failed",
                        "stage": "cancelled" if cancelled else "failed",
                        "stage_label": STAGES["cancelled" if cancelled else "failed"][0],
                        "completed_at": utc_now(),
                        "error": {"code": exc.code, "message": exc.message, "detail": exc.detail},
                    }
                )
                self._persist_failure(job)
        except Exception as exc:  # defensive job boundary
            with self.lock:
                job = self.jobs[job_id]
                job.update(
                    {
                        "status": "failed",
                        "stage": "failed",
                        "stage_label": "Failed",
                        "completed_at": utc_now(),
                        "error": {"code": "INTERNAL_ERROR", "message": "Unexpected analysis failure", "detail": str(exc)},
                    }
                )
                self._persist_failure(job)

    def _persist_failure(self, job: dict[str, Any]) -> None:
        run_dir = RUNS_DIR / job["job_id"]
        if run_dir.is_dir():
            (run_dir / "manifest.json").write_text(json.dumps(job, indent=2, ensure_ascii=False), encoding="utf-8")

    def get(self, job_id: str) -> dict[str, Any]:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            return self.public(job)

    def public(self, job: dict[str, Any]) -> dict[str, Any]:
        result = dict(job)
        job_id = job["job_id"]
        run_dir = RUNS_DIR / job_id
        result["artifacts"] = {
            name: f"/api/analyses/{job_id}/artifacts/{name}"
            for name in sorted(ARTIFACTS)
            if (run_dir / name).is_file()
        }
        return result

    def latest(self) -> dict[str, Any]:
        with self.lock:
            completed = [job for job in self.jobs.values() if job.get("status") in {"completed", "completed_with_warnings"}]
            if not completed:
                raise KeyError("latest")
            return self.public(max(completed, key=lambda job: job.get("completed_at") or ""))

    def cancel(self, job_id: str) -> dict[str, Any]:
        with self.lock:
            if job_id not in self.jobs:
                raise KeyError(job_id)
            if self.jobs[job_id]["status"] not in {"queued", "running"}:
                return self.public(self.jobs[job_id])
            self.cancel_events[job_id].set()
            return self.public(self.jobs[job_id])


pipeline = AnalysisPipeline(WORKSPACE)
manager = JobManager(pipeline)
app = FastAPI(title="NodeGoat Guardian API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)


@app.get("/api/health")
def health() -> dict[str, Any]:
    validator = pipeline._validator_path()
    return {
        "status": "ok",
        "api_version": app.version,
        "max_simultaneous_jobs": MAX_JOBS,
        "validator_available": validator is not None,
        "osv_scanner_available": pipeline._osv_path() is not None,
        "generator": f"@cyclonedx/cyclonedx-npm@{os.getenv('CYCLONEDX_NPM_VERSION', '1.19.3')}",
    }


@app.post("/api/analyses", response_model=AnalysisStatus, status_code=status.HTTP_202_ACCEPTED)
def create_analysis(request: AnalysisRequest) -> dict[str, Any]:
    try:
        return manager.create(request.repository_url)
    except PipelineError as exc:
        raise HTTPException(status_code=422, detail={"code": exc.code, "message": exc.message}) from exc


@app.get("/api/analyses/latest", response_model=AnalysisStatus)
def latest_analysis() -> dict[str, Any]:
    try:
        return manager.latest()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No completed analysis exists") from exc


@app.get("/api/analyses/{job_id}", response_model=AnalysisStatus)
def get_analysis(job_id: str) -> dict[str, Any]:
    try:
        return manager.get(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc


@app.delete("/api/analyses/{job_id}", response_model=AnalysisStatus)
def cancel_analysis(job_id: str) -> dict[str, Any]:
    try:
        return manager.cancel(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc


def _safe_run_dir(job_id: str) -> Path:
    if not job_id or any(char not in "0123456789abcdef" for char in job_id) or len(job_id) != 32:
        raise HTTPException(status_code=404, detail="Analysis not found")
    run_dir = (RUNS_DIR / job_id).resolve()
    if run_dir.parent != RUNS_DIR or not run_dir.is_dir():
        raise HTTPException(status_code=404, detail="Analysis not found")
    return run_dir


@app.get("/api/analyses/{job_id}/graph")
def get_graph(job_id: str) -> FileResponse:
    path = _safe_run_dir(job_id) / "graph.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Graph is not available")
    return FileResponse(path, media_type="application/json", filename="graph.json")


def _json_artifact(job_id: str, name: str) -> FileResponse:
    path = _safe_run_dir(job_id) / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Analysis result is not available")
    return FileResponse(path, media_type="application/json", filename=name)


@app.get("/api/analyses/{job_id}/risks")
def get_risks(job_id: str) -> FileResponse:
    return _json_artifact(job_id, "vulnerabilities.json")


@app.get("/api/analyses/{job_id}/changes")
def get_changes(job_id: str) -> FileResponse:
    return _json_artifact(job_id, "changes.json")


@app.get("/api/analyses/{job_id}/report")
def get_report(job_id: str) -> FileResponse:
    return _json_artifact(job_id, "report.json")


@app.get("/api/analyses/{job_id}/artifacts/{name}")
def get_artifact(job_id: str, name: str) -> FileResponse:
    if name not in ARTIFACTS:
        raise HTTPException(status_code=404, detail="Artifact not found")
    path = _safe_run_dir(job_id) / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")
    media_type = "application/json" if name.endswith(".json") else "text/html; charset=utf-8" if name.endswith(".html") else "text/markdown; charset=utf-8" if name.endswith(".md") else "text/plain; charset=utf-8"
    return FileResponse(path, media_type=media_type, filename=name)

