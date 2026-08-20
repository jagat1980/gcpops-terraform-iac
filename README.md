# OneShield Vulnerability Management Engine

Enterprise Multi-Agent AI Vulnerability Management Engine powered by FastAPI, LangGraph, and Model Context Protocol (MCP).

## Architecture Summary
- **FastAPI Gateway**: Webhook handling and API orchestration (`POST /v1/scan-handler`).
- **LangGraph Multi-Agent Ledger**: Secure code review, reachability analysis, SAST/DAST fixing advisors.
- **MCP Integration**: Model Context Protocol servers for security grounding & scanner ingestion.
- **GCP Infrastructure**: GKE Autopilot, Cloud SQL PostgreSQL 16, Google Artifact Registry, Cloud Armor WAF.

## Verification & Health
- Health check: `GET /health`
- Scan Handler: `POST /v1/scan-handler`
