# CloudSecOps Platform Architecture

```text
                    Security Evidence Request
                              |
                              v
                     FastAPI / Pydantic
                              |
                              v
                     SecOps Orchestrator
                              |
          +-------------------+-------------------+
          |                   |                   |
          v                   v                   v
   Configuration         Dependency          Event Pattern
     Analysis             Analysis              Analysis
          |                   |                   |
          +-------------------+-------------------+
                              |
                       Compliance Engine
                              |
                              v
                    Finding Aggregation
                              |
             +----------------+----------------+
             |                |                |
             v                v                v
          Severity         Risk Score        Summary
             |                |                |
             +----------------+----------------+
                              |
                              v
                       Structured API
                           Response
```

## Trust boundaries and limitations

- The API analyses evidence explicitly supplied by the caller.
- No cloud credentials are accepted or used.
- No cloud infrastructure is queried or modified.
- Package rules are illustrative local rules, not a live vulnerability feed.
- Threat detection is deterministic pattern matching, not machine learning.
- Compliance checks evaluate supplied control outcomes and do not certify compliance.
- The prototype is intended for engineering demonstration and local testing.
