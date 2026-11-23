from pathlib import Path

import pytest

from core.repository_inspector import inspect_repository, safe_read_text, service_for_path
from core.url_validator import InvalidRepositoryURL, validate_github_url, validate_ref

FIX = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.mark.parametrize("url,owner,name", [
    ("https://github.com/OWASP/NodeGoat", "OWASP", "NodeGoat"),
    ("https://github.com/OWASP/NodeGoat.git", "OWASP", "NodeGoat"),
    ("  https://github.com/a/b/  ", "a", "b"),
    ("https://www.github.com/a/b", "a", "b"),
])
def test_valid_urls(url, owner, name):
    r = validate_github_url(url)
    assert (r.owner, r.name) == (owner, name)
    assert r.clone_url == f"https://github.com/{owner}/{name}.git"


@pytest.mark.parametrize("url", [
    "", "C:\\repos\\x", "/etc/passwd", "file:///etc/passwd", "git@github.com:a/b.git", "http://github.com/a/b",
    "https://gitlab.com/a/b", "https://github.com/a", "https://github.com/a/b/c", "https://user:pw@github.com/a/b",
    "https://github.com:444/a/b", "https://github.com/a/b?x=1", "https://github.com/a/b#frag",
    "https://github.com/a/b; rm -rf /", "https://github.com/--upload-pack=x/b", "https://github.com/a/..",
    "https://evil.com/github.com/a/b", "ssh://github.com/a/b", "https://github.com/a/b c", "https://github.com/a/b\n",
])
def test_invalid_urls(url):
    if url == "https://github.com/a/b\n":
        # trailing whitespace is stripped -> valid; ensure embedded newline is rejected
        validate_github_url(url)
        with pytest.raises(InvalidRepositoryURL):
            validate_github_url("https://github.com/a/b\nx")
        return
    with pytest.raises(InvalidRepositoryURL):
        validate_github_url(url)


def test_non_string_rejected():
    with pytest.raises(InvalidRepositoryURL):
        validate_github_url(None)  # type: ignore[arg-type]


def test_ref_validation():
    assert validate_ref(None) is None and validate_ref(" ") is None
    assert validate_ref("feature/x-1.2") == "feature/x-1.2"
    for bad in ("--upload-pack=x", "a..b", "a b", "-x", "a//b", "x;y"):
        with pytest.raises(InvalidRepositoryURL):
            validate_ref(bad)


def test_inspect_monorepo():
    res = inspect_repository(FIX / "monorepo")
    assert {"npm", "PyPI", "Go"} <= set(res.ecosystems)
    dirs = {s["dir"] for s in res.services}
    assert {"frontend", "backend", "services/api"} <= dirs
    fw = {(h.name, h.service_dir) for h in res.frameworks}
    assert ("React", "frontend") in fw and ("Flask", "backend") in fw and ("Gin", "services/api") in fw
    assert any(m.name == "package-lock.json" and m.kind == "lockfile" for m in res.manifests)
    assert res.languages == {} or all("files" in v for v in res.languages.values())


def test_inspect_flags_unsupported_and_limits(tmp_path):
    (tmp_path / "Gemfile").write_text("gem 'rails'\n")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
    res = inspect_repository(tmp_path)
    assert res.unsupported and res.dockerfiles == ["Dockerfile"] and res.ci_files
    assert any("never built" in l for l in res.limitations)


def test_empty_repo_reports_limitation(tmp_path):
    res = inspect_repository(tmp_path)
    assert res.manifests == [] and res.limitations


def test_safe_read_blocks_traversal_and_symlink(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    (tmp_path / "secret.txt").write_text("x")
    assert safe_read_text(root, "../secret.txt") is None
    try:
        (root / "link").symlink_to(tmp_path / "secret.txt")
        assert safe_read_text(root, "link") is None
    except OSError:
        pass  # symlinks unavailable


def test_service_for_path():
    svcs = [".", "frontend", "frontend/sub"]
    assert service_for_path("frontend/sub/x.json", svcs) == "frontend/sub"
    assert service_for_path("frontend/a.json", svcs) == "frontend"
    assert service_for_path("other/a.json", svcs) == "."
