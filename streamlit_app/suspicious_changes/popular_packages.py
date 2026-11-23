"""Curated reference lists of widely used packages per ecosystem (built-in, versioned, hand-maintained).

These are a *reference set for name comparison*, not a trust list: absence from the list says nothing about a package.
Extend or replace via ``load_extra_reference`` (JSON file mapping ecosystem -> [names]).
"""
from __future__ import annotations

import json
from pathlib import Path

REFERENCE_VERSION = "builtin-2026.1"

_NPM = """
react react-dom react-router react-router-dom redux react-redux next vue vuex vue-router nuxt angular svelte
express koa fastify hapi body-parser cookie-parser cors helmet morgan compression multer passport jsonwebtoken bcrypt bcryptjs
lodash underscore moment dayjs date-fns axios request request-promise node-fetch got superagent needle
webpack webpack-cli webpack-dev-server rollup vite parcel babel-core babel-loader babel-preset-env eslint prettier typescript ts-node tslint
jest mocha chai sinon karma jasmine supertest nyc istanbul cypress puppeteer playwright selenium-webdriver
chalk commander yargs inquirer minimist optimist debug colors cli-color ora boxen figlet
async bluebird q rxjs uuid nanoid shortid moment-timezone numeral validator joi yup ajv
mongoose mongodb mysql mysql2 pg sequelize knex redis ioredis sqlite3 typeorm prisma
socket.io ws cheerio jquery bootstrap tailwindcss sass less node-sass postcss autoprefixer
dotenv cross-env rimraf mkdirp glob fs-extra del gulp grunt nodemon pm2 concurrently
semver inherits readable-stream through2 safe-buffer string_decoder util events buffer process
yaml js-yaml xml2js csv-parse marked handlebars ejs pug mustache underscore.string
aws-sdk firebase stripe twilio nodemailer sendgrid winston bunyan pino log4js
core-js regenerator-runtime tslib object-assign qs ms mime mime-types iconv-lite
object.assign safer-buffer through through2 isarray core-util-is process-nextick-args util-deprecate
@angular/core @angular/common @angular/cli @babel/core @babel/preset-env @types/node @types/react @types/jest @nestjs/core @nestjs/common
""".split()

_PYPI = """
requests urllib3 numpy pandas scipy matplotlib seaborn scikit-learn tensorflow torch keras pillow opencv-python
flask django fastapi starlette uvicorn gunicorn jinja2 werkzeug click itsdangerous markupsafe
sqlalchemy psycopg2 psycopg2-binary pymysql pymongo redis celery kombu boto3 botocore awscli s3transfer
setuptools wheel pip virtualenv six packaging pyparsing python-dateutil pytz tzdata certifi idna chardet charset-normalizer
pyyaml toml tomli simplejson ujson orjson cryptography pyopenssl paramiko bcrypt pynacl pycparser cffi
pytest pytest-cov mock nose tox coverage flake8 pylint black isort mypy pydantic attrs
beautifulsoup4 lxml html5lib scrapy selenium httpx aiohttp websockets grpcio protobuf
jsonschema pyjwt oauthlib requests-oauthlib python-dotenv tqdm colorama tabulate rich typer docopt
networkx sympy statsmodels xgboost lightgbm transformers openai anthropic streamlit gradio
django-rest-framework djangorestframework django-cors-headers whitenoise pillow-simd
""".split()

_MAVEN = """
org.springframework:spring-core org.springframework:spring-web org.springframework.boot:spring-boot-starter
com.google.guava:guava org.apache.commons:commons-lang3 commons-io:commons-io commons-codec:commons-codec
com.fasterxml.jackson.core:jackson-databind com.fasterxml.jackson.core:jackson-core org.slf4j:slf4j-api
ch.qos.logback:logback-classic org.apache.logging.log4j:log4j-core org.apache.logging.log4j:log4j-api
junit:junit org.junit.jupiter:junit-jupiter org.mockito:mockito-core org.hibernate:hibernate-core
com.google.code.gson:gson org.apache.httpcomponents:httpclient mysql:mysql-connector-java org.projectlombok:lombok
""".split()

_GO = """
github.com/gin-gonic/gin github.com/gorilla/mux github.com/stretchr/testify github.com/sirupsen/logrus
github.com/spf13/cobra github.com/spf13/viper github.com/pkg/errors github.com/golang/protobuf google.golang.org/grpc
golang.org/x/net golang.org/x/crypto golang.org/x/text golang.org/x/sys github.com/go-sql-driver/mysql github.com/lib/pq
github.com/labstack/echo github.com/gofiber/fiber github.com/google/uuid go.uber.org/zap gorm.io/gorm
""".split()

_CRATES = """
serde serde_json tokio rand clap regex syn quote proc-macro2 log env_logger anyhow thiserror chrono reqwest
hyper futures lazy_static once_cell itertools bytes libc rayon actix-web axum rocket diesel sqlx
""".split()

_PACKAGIST = """
laravel/framework symfony/console symfony/http-foundation guzzlehttp/guzzle monolog/monolog phpunit/phpunit
doctrine/orm doctrine/dbal composer/composer psr/log nesbot/carbon vlucas/phpdotenv league/flysystem twig/twig
""".split()

_NUGET = """
Newtonsoft.Json Microsoft.Extensions.Logging Microsoft.EntityFrameworkCore Serilog AutoMapper Dapper
xunit NUnit Moq FluentAssertions RestSharp Polly StackExchange.Redis System.Text.Json Microsoft.AspNetCore.App
""".split()

_RUBYGEMS = """
rails rack sinatra rspec nokogiri puma devise activerecord rake bundler json thor minitest sidekiq redis pg mysql2
""".split()

POPULAR: dict[str, list[str]] = {
    "npm": _NPM, "PyPI": _PYPI, "Maven": _MAVEN, "Go": _GO, "crates.io": _CRATES,
    "Packagist": _PACKAGIST, "NuGet": _NUGET, "RubyGems": _RUBYGEMS,
}

# npm scopes that are well known and legitimately host many packages
TRUSTED_NPM_SCOPES = {"@types", "@babel", "@angular", "@nestjs", "@aws-sdk", "@azure", "@google-cloud", "@mui", "@emotion",
                      "@testing-library", "@jest", "@vue", "@reduxjs", "@storybook", "@typescript-eslint", "@eslint"}


def load_extra_reference(path: str | Path) -> None:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for eco, names in data.items():
        POPULAR.setdefault(eco, [])
        POPULAR[eco] = sorted(set(POPULAR[eco]) | set(names))
