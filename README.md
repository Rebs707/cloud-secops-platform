# CloudSecOps Platform

An evidence-driven cloud security analysis prototype built with FastAPI and Python. It coordinates configuration checks, package-rule analysis, security-event pattern detection and compliance-control evaluation into a single structured security report.

## Capabilities

- **Configuration analysis:** identifies explicitly supplied public-access, encryption, logging and MFA risks.
- **Dependency analysis:** evaluates package declarations against a small illustrative local rule catalogue.
- **Threat pattern analysis:** identifies failed authentication, privilege escalation and policy-change events.
- **Compliance evaluation:** evaluates supplied encryption, audit logging, least-privilege and MFA control outcomes.
- **Finding aggregation:** assigns severity, evidence, recommendations, summary counts and a bounded risk score.
- **API:** provides typed request validation, health status and a rule catalogue endpoint.

## Architecture

See [the architecture diagram](diagrams/cloud-secops-architecture.md).

## Requirements

- Python 3.10+
- pip
- Docker Engine and Docker Compose (optional)

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API documentation: http://127.0.0.1:8000/docs

Health check: `GET /health`

Rule catalogue: `GET /secops/rules`

## Example scan

```bash
curl -X POST http://127.0.0.1:8000/secops/scan \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "example-storage-resource",
    "resource_type": "storage",
    "configuration": {
      "public_access": true,
      "encryption_enabled": false,
      "logging_enabled": true,
      "mfa_enabled": true
    },
    "packages": {
      "django": "1.2.0"
    },
    "events": [
      {
        "event_type": "login",
        "outcome": "failure",
        "source_ip": "192.0.2.10"
      },
      {
        "event_type": "privilege_escalation",
        "outcome": "success"
      }
    ],
    "controls": {
      "encryption_at_rest": false,
      "audit_logging": true,
      "least_privilege": null,
      "mfa": true
    }
  }'
```

The response includes an overall status, risk score, severity counts, per-agent results, normalized findings and limitations.

## Run tests

```bash
pytest -v
```

## Run with Docker Compose

```bash
docker compose up --build -d
docker compose ps
curl http://127.0.0.1:8000/health
docker compose down
```

The container runs as a non-root user with a read-only root filesystem, dropped Linux capabilities, no-new-privileges and a health check.

## Finding severity

| Severity | Meaning |
|---|---|
| Critical | Immediate high-impact exposure indicated by supplied evidence |
| High | Significant security or control weakness |
| Medium | Security concern requiring review |
| Low | Lower-impact concern |
| Info | Informational observation |

The aggregate risk score is a bounded prioritisation indicator, not a probability of compromise.

## Important limitations

This project is a deterministic prototype, not a production security product.

- It analyses only the evidence supplied in each request.
- It does not connect to AWS, Azure, GCP, Kubernetes or a SIEM.
- It does not retrieve live CVEs or establish exploitability.
- Its local package rules are illustrative and intentionally limited.
- Its event rules are simple patterns, not an AI model or behavioural analytics engine.
- Compliance checks do not constitute certification, legal advice or an independent audit.
- A resource with no supplied evidence is reported as `not_assessed`, not secure.

## Security considerations

Do not submit credentials, secrets, personal data or sensitive production logs. The API is a demonstration service and has no authentication, authorization, persistent audit store, rate limiting or tenant isolation. Do not expose it to the public internet.

## Validation

Automated tests cover configuration findings, package rules, event patterns, compliance controls, API validation, health and rule discovery. Record actual test and container results when validating a local build; no cloud deployment is implied.

## License

MIT License.
