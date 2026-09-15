# Security AI

Security AI is a small SOC-style investigation platform for authentication logs. It turns raw log text into structured security events, runs deterministic detections, stores the result, and gives an analyst one place to review detections, anomaly signals, threat-intelligence context, ATT&CK mappings and AI-assisted investigation reports.

The project is deliberately built so the AI layer is not the detection engine. Brute-force, password-spraying and credential-compromise logic runs first. ATT&CK technique IDs come from those deterministic rules, and any AI report is generated afterwards from the evidence already collected by the application.

## What is in v1.0

The current release includes:

- JWT authentication and per-user analysis ownership
- authentication-log parsing, including common OpenSSH log lines
- brute-force, password-spraying and credential-compromise detections
- IOC extraction for IP addresses, domains and common hash formats
- a local MITRE ATT&CK knowledge snapshot used to ground investigations
- optional AbuseIPDB enrichment for eligible public IP addresses
- Isolation Forest anomaly detection over stored event data
- asynchronous AI investigation reports through Celery and Redis
- persistent analyst cases, notes, assignments and timelines
- a browser dashboard built with Jinja2 and HTMX
- PostgreSQL persistence and Alembic migrations
- Docker Compose for the API, worker, PostgreSQL and Redis
- automated tests covering the main API, detection, dashboard, AI, case and security paths

At the v1.0 release point, the Python test suite contains 152 passing tests.

## How the pieces fit together

A normal analysis starts with submitted log text or a `.log` / `.txt` upload. The parser converts recognised entries into structured events. Deterministic rules then produce incidents and alerts. The complete analysis is stored in PostgreSQL and can be revisited from the API or dashboard.

From there, an analyst can run anomaly detection, link the analysis to a case, or request an AI investigation. AI work is queued instead of being performed inside the web request. The worker reloads the stored analysis, gathers ATT&CK context and optional threat-intelligence context, then asks the configured provider for a structured report. The report and the evidence used to ground it are stored with the investigation record.

The main runtime components are:

```text
Browser / API client
        |
     FastAPI
        |
   PostgreSQL
        |
  Redis -> Celery worker -> optional external AI / threat-intel providers
```

The dashboard is server-rendered and uses a self-hosted HTMX file, so there is no frontend build step for the application UI.

## Quick start with Docker

Docker Compose is the simplest way to run the full stack locally.

Create a local environment file from the example:

```powershell
Copy-Item .env.example .env
```

Before starting the stack, set a strong `JWT_SECRET_KEY` and a local PostgreSQL password in `.env`. Keep `APP_ENVIRONMENT=development` for normal HTTP development.

Build and start the services:

```powershell
docker compose up --build -d
```

Check their state:

```powershell
docker compose ps
```

The API health endpoint should return a healthy response:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

To inspect startup or worker output:

```powershell
docker compose logs api --tail 100
docker compose logs worker --tail 100
```

The API container applies Alembic migrations during startup before Uvicorn is launched.

For a clean local rebuild, stop the stack and remove the development volumes before starting it again. Only do this if you are happy to delete the local PostgreSQL data:

```powershell
docker compose down -v
docker compose up --build -d
```

More deployment notes are in [docs/deployment.md](docs/deployment.md).

## Running the tests

With the virtual environment active:

```powershell
python -m pytest
```

The tests use an in-memory SQLite database, so the main test suite does not require a running PostgreSQL or Redis service.

## Configuration

Settings are loaded through Pydantic Settings. Local development reads `.env` from the project root.

The most important values are:

| Setting | Purpose |
| --- | --- |
| `APP_ENVIRONMENT` | `development`, `test` or `production` |
| `DATABASE_URL` | Full SQLAlchemy database URL, when supplied directly |
| `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | Used to build the PostgreSQL URL when `DATABASE_URL` is not set |
| `JWT_SECRET_KEY` | Secret used to sign access tokens; minimum 32 characters |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access-token lifetime |
| `AI_PROVIDER` | `disabled` or `openai` |
| `OPENAI_API_KEY` | Required when the OpenAI provider is enabled |
| `OPENAI_MODEL` | Model used for investigation reports |
| `AI_REQUEST_TIMEOUT_SECONDS` | AI request timeout |
| `AI_MAX_INPUT_CHARS` | Maximum evidence payload sent to the AI provider |
| `CELERY_BROKER_URL` | Redis URL used by Celery |
| `THREAT_INTEL_PROVIDER` | `disabled` or `abuseipdb` |
| `ABUSEIPDB_API_KEY` | Required when AbuseIPDB enrichment is enabled |
| `THREAT_INTEL_CACHE_TTL_HOURS` | Lifetime of successful cached enrichment results |

AI and threat-intelligence integrations are optional. The application still performs parsing, deterministic detections, persistence, anomaly analysis and case work with both providers disabled.

## Main application areas

The API is split into a few obvious areas rather than one large endpoint surface.

Authentication handles registration and token issuance. Analysis endpoints accept authentication logs, persist results and expose analysis history. Anomaly endpoints run the ML detector over stored analysis data. AI-report endpoints queue and return investigation reports. Case endpoints handle longer-running analyst investigations.

The browser UI lives under `/dashboard` and provides recent analyses, investigation workspaces and case management without requiring a separate JavaScript application.

## AI is supporting evidence, not authority

There are several guardrails around the investigation layer. Raw logs are treated as untrusted input, ATT&CK references are restricted to techniques already supplied by the deterministic pipeline, structured responses are validated, and the exact grounding context is stored with the report.

Threat-intelligence data is handled the same way: it can support an investigation, but it is not treated as proof that an event is malicious. Failed enrichment is recorded as a failure rather than being interpreted as a clean result.

See [docs/ai-grounding.md](docs/ai-grounding.md) and [docs/threat_intelligence.md](docs/threat_intelligence.md) for the details.

## Project documentation

- [AI grounding](docs/ai-grounding.md) — how ATT&CK context and evidence are kept under control
- [Asynchronous investigations](docs/async-investigations.md) — API, Redis and Celery report flow
- [Case management](docs/cases.md) — case visibility, notes, assignment and timelines
- [Threat intelligence](docs/threat_intelligence.md) — IOC extraction, AbuseIPDB and caching
- [Deployment](docs/deployment.md) — production configuration and operational checks
- [Security notes](docs/security.md) — trust boundaries, browser protections and deployment assumptions

## Release status

v1.0 is the first complete release of the project. The application has been exercised through the full test suite, a clean Docker build, fresh-database migrations, API and worker startup, and the `/health` endpoint.

The project is still a portfolio / reference implementation rather than a replacement for a production SIEM or EDR platform. A real internet-facing deployment should put the application behind TLS, use managed secrets, add edge rate limiting and establish normal operational controls such as backups, monitoring and log retention.
