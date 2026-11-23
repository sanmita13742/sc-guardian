from pathlib import Path

from sbom.lockfile_analyzer import analyze_repository, parse_text
from sbom.package_extractors.common import classify_source, make_purl, normalize_name, parse_purl
from core.repository_inspector import inspect_repository

FIX = Path(__file__).resolve().parent.parent / "fixtures"
E = FIX / "ecosystems"


def rd(p):
    return (E / p).read_text(encoding="utf-8")


def by_name(deps):
    return {d.name: d for d in deps}


def test_purl_roundtrip():
    assert make_purl("npm", "@babel/core", "7.0.0") == "pkg:npm/%40babel/core@7.0.0"
    p = parse_purl("pkg:npm/%40babel/core@7.0.0")
    assert p["osv_name"] == "@babel/core" and p["ecosystem"] == "npm" and p["version"] == "7.0.0"
    assert make_purl("Maven", "org.x:y", "1") == "pkg:maven/org.x/y@1"
    assert parse_purl("pkg:maven/org.x/y@1")["osv_name"] == "org.x:y"
    assert parse_purl("pkg:golang/github.com/a/b@v1.0.0")["osv_name"] == "github.com/a/b"
    assert parse_purl("pkg:deb/debian/curl@7")["ecosystem"] is None
    assert parse_purl("garbage") is None
    assert normalize_name("PyPI", "Foo_Bar.baz") == "foo-bar-baz"


def test_classify_source():
    assert classify_source("https://registry.npmjs.org/x/-/x-1.tgz") == "registry"
    assert classify_source("git+ssh://git@github.com/a/b.git") == "git"
    assert classify_source("https://evil.example/x.tgz") == "url"
    assert classify_source("file:../x") == "path"
    assert classify_source(None) == "unknown"


def test_package_lock_v3():
    deps = by_name(parse_text("package-lock.json", (FIX / "monorepo/frontend/package-lock.json").read_text(),
                              "frontend/package-lock.json", "frontend"))
    assert deps["lodash"].direct is True and deps["lodash"].version == "4.17.15"
    assert deps["minimist"].direct is False
    assert deps["mkdirp"].requires == ["minimist"]
    assert deps["jest"].dev is True and deps["jest"].direct is True
    assert deps["lodash"].purl == "pkg:npm/lodash@4.17.15"
    assert deps["lodash"].integrity.startswith("sha512-") and deps["lodash"].source_type == "registry"


def test_package_lock_v1():
    text = '{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","requires":{"b":"^1"},"dependencies":{"b":{"version":"1.1.0"}}}}}'
    deps = parse_text("package-lock.json", text, "package-lock.json", ".", {"package_json": '{"dependencies":{"a":"1"}}'})
    d = by_name(deps)
    assert d["a"].direct is True and d["b"].direct is False and d["a"].requires == ["b"]


def test_yarn_lock():
    deps = by_name(parse_text("yarn.lock", rd("yarn.lock"), "yarn.lock", ".",
                              {"package_json": '{"dependencies":{"lodash":"^4.17.0"}}'}))
    assert deps["lodash"].version == "4.17.15" and deps["lodash"].direct is True
    assert deps["@babel/code-frame"].requires == ["@babel/highlight"]
    assert deps["@babel/highlight"].direct is False


def test_pnpm_lock():
    deps = by_name(parse_text("pnpm-lock.yaml", rd("pnpm-lock.yaml"), "pnpm-lock.yaml", "."))
    assert deps["lodash"].direct is True and deps["ms"].direct is False and deps["ms"].dev is True


def test_requirements():
    deps = by_name(parse_text("requirements.txt", "Flask==0.12.2\nrequests>=2\n-r other.txt\n# c\nPyYAML == 5.1 --hash=sha256:abc\nfoo[bar]==1.0; python_version<'3'\n",
                              "requirements.txt", "."))
    assert deps["flask"].version == "0.12.2" and deps["flask"].purl == "pkg:pypi/flask@0.12.2"
    assert deps["requests"].version is None  # unpinned must not invent a version
    assert deps["pyyaml"].version == "5.1" and deps["pyyaml"].integrity == "sha256:abc"
    assert deps["foo"].version == "1.0"


def test_poetry_uv_pipfile():
    d = by_name(parse_text("poetry.lock", rd("poetry.lock"), "poetry.lock", ".", {"pyproject": rd("pyproject.toml")}))
    assert d["django"].direct is True and d["pytz"].direct is False and d["pytest"].dev is True
    assert d["django"].requires == ["pytz", "sqlparse"]
    u = by_name(parse_text("uv.lock", rd("uv.lock"), "uv.lock", "."))
    assert u["httpx"].direct is True and u["certifi"].direct is False and "demo" not in u
    p = by_name(parse_text("Pipfile.lock", rd("Pipfile.lock"), "Pipfile.lock", "."))
    assert p["requests"].version == "2.19.1" and p["pytest"].dev is True


def test_go():
    mod = by_name(parse_text("go.mod", (FIX / "monorepo/services/api/go.mod").read_text(), "go.mod", "."))
    assert mod["github.com/gin-gonic/gin"].direct is True and mod["golang.org/x/text"].direct is False
    s = parse_text("go.sum", (FIX / "monorepo/services/api/go.sum").read_text(), "go.sum", ".")
    assert len(s) == 2 and all(x.integrity.startswith("h1:") for x in s)


def test_cargo_composer_nuget_maven():
    c = by_name(parse_text("Cargo.lock", rd("Cargo.lock"), "Cargo.lock", "."))
    assert "demo-app" not in c and c["serde"].direct is True and c["serde_derive"].direct is False
    assert c["smallvec"].source_type == "registry"
    p = by_name(parse_text("composer.lock", rd("composer.lock"), "composer.lock", ".", {"composer_json": '{"require":{"monolog/monolog":"^2"}}'}))
    assert p["monolog/monolog"].version == "2.0.0" and p["monolog/monolog"].direct is True and p["phpunit/phpunit"].dev is True
    n = by_name(parse_text("packages.lock.json", rd("packages.lock.json"), "packages.lock.json", "."))
    assert n["Newtonsoft.Json"].direct is True and n["System.Text.Encodings.Web"].direct is False
    m = by_name(parse_text("pom.xml", rd("pom.xml"), "pom.xml", "."))
    assert m["org.apache.logging.log4j:log4j-core"].version == "2.14.1"
    assert m["com.google.guava:guava"].version == "31.0-jre"  # from dependencyManagement
    assert m["junit:junit"].dev is True


def test_malformed_files_do_not_crash(tmp_path):
    (tmp_path / "package-lock.json").write_text("{not json")
    (tmp_path / "Cargo.lock").write_text("[[package")
    (tmp_path / "pom.xml").write_text("<project>")
    insp = inspect_repository(tmp_path)
    deps, errors = analyze_repository(tmp_path, insp)
    assert deps == [] and len(errors) >= 2


def test_analyze_monorepo():
    root = FIX / "monorepo"
    deps, errors = analyze_repository(root, inspect_repository(root))
    assert not errors
    eco = {d.ecosystem for d in deps}
    assert eco == {"npm", "PyPI", "Go"}
