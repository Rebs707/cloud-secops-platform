# CloudSecOps Platform Architecture

```text
                 Agentic Control Plane (ACP)
                           |
                           v
                  CloudSecOps Platform
                           |
    ------------------------------------------------
    |                 |                |            |
Security Scan   Vulnerability   Threat Detection  Compliance
   Agent           Agent            Agent           Agent
       \              |                |             /
        \             |                |            /
              -------- SecOps Workflow --------
                           |
             --------------------------------
             |              |               |
       Security Scanner  CVE Engine   Policy Engine
                           |
                           v
                 Cloud Infrastructure
