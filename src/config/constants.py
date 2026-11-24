"""Static tables shared across modules."""

IGNORED_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target",
    ".tox", ".mypy_cache", ".pytest_cache", "bower_components", ".idea", ".vscode", ".guardian",
}

EXTENSION_LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".kt": "Kotlin", ".go": "Go",
    ".rs": "Rust", ".cs": "C#", ".php": "PHP", ".rb": "Ruby", ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".hpp": "C++", ".swift": "Swift", ".scala": "Scala",
    ".sh": "Shell", ".ps1": "PowerShell", ".html": "HTML", ".css": "CSS", ".vue": "Vue",
}
MARKUP_LANGUAGES = {"HTML", "CSS"}

# file name -> (kind, ecosystem). kind: manifest | lockfile
MANIFEST_FILES = {
    "package.json": ("manifest", "npm"),
    "package-lock.json": ("lockfile", "npm"),
    "npm-shrinkwrap.json": ("lockfile", "npm"),
    "yarn.lock": ("lockfile", "npm"),
    "pnpm-lock.yaml": ("lockfile", "npm"),
    "requirements.txt": ("lockfile", "PyPI"),  # pinned requirements act as resolution
    "pyproject.toml": ("manifest", "PyPI"),
    "setup.py": ("manifest", "PyPI"),
    "Pipfile": ("manifest", "PyPI"),
    "Pipfile.lock": ("lockfile", "PyPI"),
    "poetry.lock": ("lockfile", "PyPI"),
    "uv.lock": ("lockfile", "PyPI"),
    "pom.xml": ("manifest", "Maven"),
    "build.gradle": ("manifest", "Maven"),
    "build.gradle.kts": ("manifest", "Maven"),
    "gradle.lockfile": ("lockfile", "Maven"),
    "go.mod": ("manifest", "Go"),
    "go.sum": ("lockfile", "Go"),
    "Cargo.toml": ("manifest", "crates.io"),
    "Cargo.lock": ("lockfile", "crates.io"),
    "composer.json": ("manifest", "Packagist"),
    "composer.lock": ("lockfile", "Packagist"),
    "packages.lock.json": ("lockfile", "NuGet"),
    "Gemfile": ("manifest", "RubyGems"),
    "Gemfile.lock": ("lockfile", "RubyGems"),
}
MANIFEST_SUFFIXES = {".csproj": ("manifest", "NuGet"), ".fsproj": ("manifest", "NuGet"), ".vbproj": ("manifest", "NuGet")}

CI_FILE_PATTERNS = (".github/workflows/", ".gitlab-ci.yml", "Jenkinsfile", ".circleci/", "azure-pipelines.yml",
                    ".travis.yml", "bitbucket-pipelines.yml", "Procfile")

# PURL type -> OSV ecosystem
PURL_TO_OSV = {
    "npm": "npm", "pypi": "PyPI", "golang": "Go", "cargo": "crates.io", "maven": "Maven",
    "composer": "Packagist", "nuget": "NuGet", "gem": "RubyGems",
}
OSV_TO_PURL = {v: k for k, v in PURL_TO_OSV.items()}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

FRAMEWORK_HINTS = {
    "npm": {
        "react": "React", "next": "Next.js", "vue": "Vue.js", "@angular/core": "Angular", "svelte": "Svelte",
        "express": "Express", "@nestjs/core": "NestJS", "koa": "Koa", "fastify": "Fastify", "hapi": "Hapi",
        "@hapi/hapi": "Hapi", "nuxt": "Nuxt", "gatsby": "Gatsby", "electron": "Electron", "vite": "Vite",
        "jest": "Jest", "mocha": "Mocha", "grunt": "Grunt", "webpack": "Webpack",
    },
    "PyPI": {
        "django": "Django", "flask": "Flask", "fastapi": "FastAPI", "streamlit": "Streamlit", "tornado": "Tornado",
        "pyramid": "Pyramid", "starlette": "Starlette", "aiohttp": "aiohttp", "celery": "Celery",
        "pytest": "pytest", "pandas": "pandas", "numpy": "NumPy", "torch": "PyTorch", "tensorflow": "TensorFlow",
    },
    "Maven": {
        "spring-boot": "Spring Boot", "springframework": "Spring", "quarkus": "Quarkus", "micronaut": "Micronaut",
        "jakarta": "Jakarta EE", "struts": "Apache Struts", "junit": "JUnit",
    },
    "Go": {"gin-gonic/gin": "Gin", "labstack/echo": "Echo", "gofiber/fiber": "Fiber", "gorilla/mux": "Gorilla Mux"},
    "crates.io": {"actix-web": "Actix Web", "rocket": "Rocket", "axum": "Axum", "tokio": "Tokio", "warp": "Warp"},
    "Packagist": {"laravel/framework": "Laravel", "symfony/": "Symfony", "slim/slim": "Slim", "cakephp/cakephp": "CakePHP"},
    "NuGet": {"Microsoft.AspNetCore": "ASP.NET Core", "Microsoft.EntityFrameworkCore": "Entity Framework Core",
              "xunit": "xUnit", "NUnit": "NUnit"},
    "RubyGems": {"rails": "Ruby on Rails", "sinatra": "Sinatra"},
}
FRAMEWORK_CONFIG_FILES = {
    "manage.py": "Django", "next.config.js": "Next.js", "next.config.mjs": "Next.js", "angular.json": "Angular",
    "vite.config.js": "Vite", "vite.config.ts": "Vite", "nuxt.config.js": "Nuxt", "svelte.config.js": "Svelte",
    "artisan": "Laravel", "gatsby-config.js": "Gatsby", "Gruntfile.js": "Grunt", "webpack.config.js": "Webpack",
}
