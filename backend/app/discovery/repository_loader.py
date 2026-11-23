import os
import subprocess
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Optional

from app.models.schemas import RepositoryMetadata
from app.core.logging import logger

LANGUAGE_EXTENSIONS = {
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".py": "Python",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".php": "PHP",
    ".cs": "C#",
    ".c": "C",
    ".cpp": "C++",
    ".html": "HTML",
    ".css": "CSS",
}

MANIFEST_FILES = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "pyproject.toml": "pip/poetry",
    "Pipfile": "pipenv",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "go.mod": "go",
    "Gemfile": "bundler",
    "Cargo.toml": "cargo",
}

LOCKFILES = {
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "poetry.lock": "poetry",
    "Pipfile.lock": "pipenv",
    "go.sum": "go",
    "Cargo.lock": "cargo",
}

IGNORED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".idea",
    ".vscode",
    ".next",
    ".nuxt",
}


class RepositoryLoader:
    """
    Safely inspects repository structure, identifies manifests, lockfiles,
    Dockerfiles, CI/CD pipelines, and extracts repository metadata without
    executing repository code.
    """

    @staticmethod
    def extract_zip(zip_path: Path, target_dir: Path) -> Path:
        """
        Extracts ZIP with strict path traversal protection.
        """
        target_dir.mkdir(parents=True, exist_ok=True)
        resolved_target = target_dir.resolve()

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # Prevent Zip Slip / path traversal
                dest_path = (resolved_target / member.filename).resolve()
                if not str(dest_path).startswith(str(resolved_target)):
                    raise ValueError(f"Dangerous path traversal detected in ZIP: {member.filename}")
            zip_ref.extractall(target_dir)

        logger.info(f"Safely extracted ZIP to {target_dir}")
        return target_dir

    @staticmethod
    def get_git_metadata(repo_path: Path) -> Dict[str, Optional[str]]:
        """
        Extracts git commit hash and branch name if git metadata is present.
        """
        commit_hash = None
        branch = None

        try:
            # Check if repo_path or parent has git
            res_hash = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=False
            )
            if res_hash.returncode == 0:
                commit_hash = res_hash.stdout.strip()

            res_branch = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=False
            )
            if res_branch.returncode == 0:
                branch = res_branch.stdout.strip()
        except Exception as e:
            logger.debug(f"Git metadata retrieval failed: {e}")

        return {"commit_hash": commit_hash, "branch": branch}

    @classmethod
    def inspect(cls, repo_path: Path) -> RepositoryMetadata:
        """
        Inspects repository structure and discovers manifests, lockfiles, configs.
        """
        repo_path = repo_path.resolve()
        if not repo_path.exists() or not repo_path.is_dir():
            raise FileNotFoundError(f"Target repository path does not exist: {repo_path}")

        languages_found = set()
        package_managers_found = set()
        manifests = []
        lockfiles = []
        dockerfiles = []
        docker_compose_files = []
        cicd_files = []

        for root, dirs, files in os.walk(repo_path):
            # Exclude ignored directories in-place so os.walk skips them
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

            rel_root = Path(root).relative_to(repo_path)

            for file in files:
                rel_file_path = str(rel_root / file) if str(rel_root) != "." else file
                ext = Path(file).suffix.lower()

                # Language detection
                if ext in LANGUAGE_EXTENSIONS:
                    languages_found.add(LANGUAGE_EXTENSIONS[ext])

                # Manifests
                if file in MANIFEST_FILES:
                    manifests.append(rel_file_path)
                    package_managers_found.add(MANIFEST_FILES[file])

                # Lockfiles
                if file in LOCKFILES:
                    lockfiles.append(rel_file_path)
                    package_managers_found.add(LOCKFILES[file])

                # Dockerfiles
                if file == "Dockerfile" or file.endswith(".dockerfile") or file.startswith("Dockerfile."):
                    dockerfiles.append(rel_file_path)

                # Docker Compose
                if file.startswith("docker-compose") and (file.endswith(".yml") or file.endswith(".yaml")):
                    docker_compose_files.append(rel_file_path)

                # CI/CD Workflows
                is_github_action = ".github" in rel_root.parts and "workflows" in rel_root.parts and (file.endswith(".yml") or file.endswith(".yaml"))
                is_travis = file == ".travis.yml"
                is_gitlab = file == ".gitlab-ci.yml"
                is_jenkins = file in ("Jenkinsfile", "jenkinsfile")

                if is_github_action or is_travis or is_gitlab or is_jenkins:
                    cicd_files.append(rel_file_path)

        git_meta = cls.get_git_metadata(repo_path)

        metadata = RepositoryMetadata(
            repository=repo_path.name,
            path=str(repo_path),
            languages=sorted(list(languages_found)),
            package_managers=sorted(list(package_managers_found)),
            manifests=sorted(manifests),
            lockfiles=sorted(lockfiles),
            dockerfiles=sorted(dockerfiles),
            docker_compose_files=sorted(docker_compose_files),
            cicd_files=sorted(cicd_files),
            commit_hash=git_meta.get("commit_hash"),
            branch=git_meta.get("branch"),
            status="discovered"
        )

        logger.info(
            f"Discovery completed for {repo_path.name}: "
            f"Languages={metadata.languages}, Manifests={metadata.manifests}, Lockfiles={metadata.lockfiles}"
        )
        return metadata
