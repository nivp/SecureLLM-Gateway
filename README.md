# SecureLLM Gateway

SecureLLM Gateway is a TypeScript/Express service that centralizes security controls for LLM calls. It authenticates internal callers, rate-limits per API key, detects prompt injection, redacts inbound PII before provider calls, validates untrusted model output, and writes MongoDB audit records for allowed, blocked, and error outcomes.

## Run Locally

```bash
npm install
cp .env.example .env
npm run build
npm run seed:keys
npm run dev
```

With containers:

```bash
docker compose up --build
```

The compose file starts the API, MongoDB, Redis, and Ollama. The default local model alias points challenge model names to OpenAI's `gpt-oss:20b`, which is the GPT-OSS variant intended for higher-end consumer GPUs such as a 24 GB RTX 3090. Pull it before using live chat:

```bash
docker compose exec ollama ollama pull gpt-oss:20b
```

## Environment

- `MONGODB_URI`: Mongo connection string.
- `REDIS_URL`: Redis connection string.
- `CLIENT_API_KEY`, `ADMIN_API_KEY`: demo keys consumed by `npm run seed:keys`.
- `OPENAI_API_KEY`: provider key. Use a real OpenAI key for OpenAI, or `ollama` for local Ollama compatibility.
- `OPENAI_BASE_URL`: optional OpenAI-compatible endpoint, for example `http://ollama:11434/v1`.
- `OPENAI_MODEL_ALIASES`: JSON map from public request model to provider model, for example `{"gpt-4o":"gpt-oss:20b"}`.
- `PII_ENCRYPTION_KEY`: secret used to encrypt reversible PII token mappings in audit records.

## API

`POST /v1/chat` requires `x-api-key` and a body:

```json
{
  "model": "gpt-4o",
  "messages": [{ "role": "user", "content": "Hello" }],
  "max_tokens": 1024
}
```

`GET /v1/audit?since=<iso>&limit=<1..500>&reveal_pii=false` is admin-only.

`GET /healthz` is unauthenticated and reports Mongo, Redis, and provider readiness independently.

## Security Architecture

Authentication stores only salted PBKDF2 API-key hashes plus a deterministic key ID for lookup. Verification recomputes the hash and uses constant-time comparison. Roles are `client` and `admin`; only admins can read audit logs.

Rate limiting uses a Redis sorted-set sliding window keyed by API-key ID. Each key has a configurable requests-per-minute limit, defaulting to 30.

Prompt-injection detection is an independent middleware that normalizes message text and matches multiple attack classes: role override, instruction hierarchy abuse, hidden prompt exfiltration, delimiter smuggling, data exfiltration, and jailbreak personas. Blocked requests return `400` and are audit-logged.

PII redaction runs before the provider call. It replaces emails, Israeli/international phone numbers, and Israeli national IDs with tokens such as `[PII_EMAIL_1]`. Original values are encrypted into audit metadata when `PII_ENCRYPTION_KEY` is configured, so admin audit review can reveal them without logging raw PII.

Output validation treats provider output as untrusted. It blocks OpenAI-style keys, JWT-shaped strings, AWS access keys, and output that matches prompt-injection signatures.

Audit logging records timestamp, API-key ID, model, request/response hashes, detected threat IDs, latency, status, HTTP status, and encrypted PII token metadata. Request and response bodies are not stored raw.

Secrets handling keeps provider keys and demo API keys in env vars only. `.gitleaks.toml` includes rules for common LLM and cloud secret formats.

## Appendix Fixture

The original Appendix A should not be pasted wholesale into AI tools. Add sanitized/manual cases to `test/fixtures/adversarial-cases.json`:

```json
[
  {
    "id": "case-id",
    "category": "prompt_injection",
    "input": "attack or PII string to test",
    "expectedThreats": ["role-override"]
  }
]
```

The unit tests automatically load this file. Keep the original appendix out of prompts and paste only into the local fixture.

## Known Limitations

This is a compact challenge implementation, not a complete LLM firewall. Regex/signature detection will miss novel attacks, OCR/image prompt injection is out of scope, PII detection is limited to the required categories, and output validation cannot prove absence of sensitive data. Production hardening would add managed secret storage, more telemetry, append-only audit storage, provider retries with circuit breaking, richer adversarial corpora, and CI secret scanning against git history.
