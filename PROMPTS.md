# AI Process Log

## Tools Used

- ChatGPT/Codex: repository inspection, implementation changes, security audit, test updates, Docker hardening, and documentation updates.
- Second AI tool: not yet completed in this repository state. Before final challenge submission, run an independent second-tool review against the same solution files and replace this sentence with the exact tool name, prompts, and changes. Do not fabricate this section.

## Why Multiple Tools

The challenge expects at least two AI tools to touch the same solution files. In this current repo state, Codex has touched the security-sensitive implementation and documentation, including `src/config.ts`, `test/app.test.ts`, `Dockerfile`, `docker-compose.yml`, `README.md`, and this file.

The required second-tool pass is still pending. The intended use is to ask another AI tool to challenge the security controls and tests on the same files, especially `src/security/injectionDetector.ts`, `src/security/piiRedactor.ts`, `src/security/outputValidator.ts`, `src/middleware/auth.ts`, `src/routes/audit.ts`, and `src/config.ts`. Record exactly what that tool suggested, which files it changed, and what was rejected.

## Three Example Prompts

### Example 1 (Development)

Sent to ChatGPT:

```
I'd like to create a code quality review prompt for an agent. Please make a suggestion.
```

Response piped to the Codex Agent:

```
You are a senior software engineer performing a code quality review.

Your goal is to review the provided code for correctness, maintainability, readability, robustness, security, and performance. Focus on practical, actionable feedback rather than stylistic nitpicks.

Review the code according to the following dimensions:

1. Correctness
- Identify logic bugs, edge cases, incorrect assumptions, race conditions, and error-handling gaps.
- Check whether the implementation appears to satisfy the stated requirements.
- Point out places where behavior is ambiguous or under-specified.

2. Maintainability
- Identify code that is hard to understand, overly coupled, duplicated, or difficult to extend.
- Suggest simplifications where the current design is unnecessarily complex.
- Flag unclear naming, hidden side effects, and confusing control flow.

3. Robustness
- Check input validation, exception handling, retries, timeouts, resource cleanup, null/empty cases, and boundary conditions.
- Look for places where failures may be swallowed, misreported, or cause inconsistent state.

4. Security
- Look for injection risks, unsafe deserialization, credential leakage, weak authorization checks, insecure defaults, unsafe file/network access, and sensitive data exposure.
- Do not invent vulnerabilities; only report plausible issues based on the code.

5. Performance
- Identify inefficient algorithms, unnecessary repeated work, avoidable I/O, excessive memory usage, and scalability bottlenecks.
- Prioritize issues that are likely to matter in realistic usage.

6. Testing
- Identify missing or weak tests.
- Suggest important unit, integration, regression, and edge-case tests.
- Call out code that is difficult to test and explain why.

Output format:

Start with a short overall assessment:
- What the code does well
- Main risks
- Whether the code is safe to merge as-is

Then provide findings grouped by severity:

## Critical
Issues that can cause data loss, security exposure, major outages, or clearly incorrect behavior.

## High
Issues that are likely to cause bugs, poor reliability, or significant maintenance problems.

## Medium
Issues that should be improved but are not immediately dangerous.

## Low / Suggestions
Minor improvements, readability suggestions, or optional refactors.

For each finding, include:
- Title
- Severity
- Location: file/function/line if available
- Problem
- Why it matters
- Suggested fix
- Optional improved code snippet, if useful

Rules:
- Be specific and concrete.
- Prefer fewer high-quality findings over many generic comments.
- Do not comment on formatting unless it affects readability or maintainability.
- Do not suggest large rewrites unless clearly justified.
- If information is missing, state the assumption you are making.
- If the code looks good in an area, say so briefly rather than forcing an issue.
- Avoid vague comments like “improve error handling” without explaining where and how.
- Distinguish confirmed bugs from possible risks.
```

### Example 2 (Security audit)

### Code Generation

Verbatim prompt:

> PLEASE IMPLEMENT THIS PLAN:
>
> # SecureLLM Gateway Plan
>
> ## Summary
>
> Build a fresh TypeScript/Express service in the empty repo that implements the challenge gateway end to end: authenticated `/v1/chat`, admin-only `/v1/audit`, `/healthz`, Mongo audit storage, Redis sliding-window rate limiting, independent security middlewares, tests, Docker, README, `.gitleaks.toml`, and `PROMPTS.md`.
>
> Provider integration will use the official OpenAI-style client path with configurable `OPENAI_BASE_URL`: real OpenAI when pointed at OpenAI, local Ollama when pointed at `http://ollama:11434/v1`. Ollama’s OpenAI-compatible `/v1/chat/completions` support is documented at https://docs.ollama.com/api/openai-compatibility.
>
> ## Key Changes
>
> - Create a strict TypeScript Node service using Express, Zod validation, MongoDB/Mongoose, Redis/ioredis, pino logging, Vitest, and Supertest.
> - Implement request pipeline for `POST /v1/chat`:
>   1. correlation ID and structured logging
>   2. `x-api-key` auth with hashed keys from Mongo and constant-time comparison
>   3. per-key Redis sliding-window rate limit, default `30 req/min`
>   4. body/model validation with configurable model allowlist and aliases
>   5. prompt-injection detection on every inbound message
>   6. inbound PII redaction before provider call
>   7. provider call or `503` when provider config is missing/unreachable
>   8. outbound validation before returning model output
>   9. Mongo audit record for allowed, blocked, and error outcomes
> - Add seed script for local/demo API keys:
>   - reads `CLIENT_API_KEY`, `ADMIN_API_KEY`, optional per-key rate limits
>   - stores only salted hashes/key IDs/roles in Mongo
> - Add Appendix fixture support without embedding the original appendix in prompts:
>   - `test/fixtures/adversarial-cases.json`
>   - documented schema for manually adding cases: `id`, `category`, `input`, `expectedThreats`
>   - tests load this fixture automatically when populated
> - Add `PROMPTS.md` with honest process notes:
>   - first AI interaction is this Codex/ChatGPT session and the user’s first prompt verbatim
>   - note sanitized handling of the challenge brief
>   - reserve exact entries for a second AI tool security review/debugging pass on the same solution files
>
> ## Public Interfaces
>
> - `POST /v1/chat`
>   - header: `x-api-key`
>   - body: `{ model, messages, max_tokens }`
>   - supports configured aliases, for example `gpt-4o -> llama3.2` in local Ollama mode
>   - returns `400` for detected inbound threats, `429` for rate limit, `503` for provider unavailable
> - `GET /v1/audit?since=<iso>&limit=<1..500>&reveal_pii=false`
>   - admin only
>   - returns audit records with hashes, status, threats, latency, model, key ID
>   - `reveal_pii=true` decrypts token mappings for admin audit review when `PII_ENCRYPTION_KEY` is configured
> - `GET /healthz`
>   - no auth
>   - reports Mongo, Redis, and provider readiness separately
>
> ## Security Controls
>
> - Prompt injection detector will combine named regex/signature rules and normalization for role override, instruction hierarchy attacks, data exfiltration requests, delimiter/prompt-leak probes, tool/system prompt extraction, and common realistic variations.
> - PII redaction will detect email, Israeli/international phone numbers, and Israeli national IDs; replacements use stable per-request tokens like `[PII_EMAIL_1]`.
> - Reversibility will store original PII encrypted in Mongo audit metadata using env-provided AES key; raw PII will not be logged.
> - Output validation will block secret-like output patterns including OpenAI-style `sk-...`, JWT-shaped strings, AWS access keys, and echoes of previously detected injection text/signatures.
> - Secrets handling will rely only on env vars, redact logs, and include `.gitleaks.toml` plus README guidance.
>
> ## Test Plan
>
> - Unit tests for auth hashing/role enforcement, constant-time comparison path, rate limiter behavior with Redis mocked or test Redis, prompt injection detection, PII redaction/reversal, output validation, and audit record creation.
> - Integration tests for:
>   - missing/invalid API key
>   - client denied from `/v1/audit`
>   - admin audit access with limit capped at 500
>   - blocked injection writes audit record
>   - PII is redacted before provider call
>   - missing provider returns `503` while service starts
> - Fixture-driven adversarial tests load manually supplied appendix cases from `test/fixtures/adversarial-cases.json`.
> - Docker verification target: `docker compose up` starts service, Mongo, Redis, and optional Ollama; app remains healthy except provider readiness when no model/key is configured.
>
> ## Assumptions
>
> - The repo currently contains only `Sanitized_Task.txt`; no existing code or `Prompt.md`/`PROMPTS.md` was found.
> - The original Appendix A will not be pasted into AI tools. The implementation will provide a documented fixture format, and the user will manually insert cases.
> - Use npm unless implementation later discovers a repo-level package-manager constraint.
> - Use dual provider mode: OpenAI-compatible SDK/client with `OPENAI_BASE_URL`, `OPENAI_API_KEY`, and `OPENAI_MODEL_ALIASES`; local Ollama uses a placeholder API key because Ollama ignores it.

What I did with the output: used it to generate the initial TypeScript/Express service, security modules, tests, Docker files, README, and this process document.

### Security Review

Verbatim prompt:

> You are a senior application security engineer performing a security audit.
>
> Your task is to review the provided code, configuration, infrastructure, API design, architecture notes, logs, or documentation for security weaknesses. Be rigorous, concrete, and evidence-based. Prioritize real exploitable risks over theoretical or generic concerns.
>
> Assume the reviewed system may eventually run in production and may handle sensitive data, authentication, authorization, user input, secrets, network communication, files, databases, cloud resources, containers, CI/CD pipelines, and third-party dependencies.
>
> Your goals are to:
>
> 1. Identify vulnerabilities and insecure design choices.
> 2. Explain how each issue could realistically be exploited.
> 3. Assess severity and likelihood.
> 4. Recommend concrete remediations.
> 5. Identify missing controls, tests, monitoring, or hardening measures.
> 6. Distinguish confirmed vulnerabilities from possible risks and assumptions.

What I did with the output: narrowed the initial audit recommendations against `Sanitized_Task.txt`, removed recommendations that were unrelated to the challenge requirements, and implemented the before-submission items that remained relevant.

### Debugging

Verbatim prompt:

> Please review "Sanitized Task" and check if any of your recommendation are not required per the definitions there.

What I did with the output: reclassified production-only items as optional hardening, kept the health endpoint behavior aligned with the task, and avoided treating unrelated production controls as challenge blockers.

Follow-up implementation prompt:

> Let's implement the Immediate / Before Submission recommendations and update PROMPTS.md as instructed by the task. Additionally, use Non-Root containers.

What I did with the output: removed public Compose port mappings for backing services, added production validation for placeholder PII encryption keys, added audit PII reveal tests, updated README limitations, and changed the Docker runtime container to run as the non-root `node` user.

## What I Rejected

I rejected the recommendation to hide detailed `/healthz` dependency status because `Sanitized_Task.txt` explicitly requires unauthenticated health reporting for Mongo, Redis, and provider readiness. I kept `/healthz` as a challenge requirement and treated any private-readiness redesign as out of scope.

I also rejected making a break-glass PII reveal workflow mandatory for this submission. The task requires admin-only audit access and reversible PII at audit time; separate PII permissions are documented as production hardening instead of implemented as a challenge blocker.

## What I Would Do With More Time

- Run a genuine second-tool review before final submission, have it touch the same solution files, and update this document with the exact tool name, prompts, accepted changes, and rejected suggestions.
- Add a larger manually curated Appendix A fixture set and mutation tests for spacing, casing, delimiter, and homoglyph variations. AI would help generate variants only after the original cases are manually sanitized into local fixtures.
- Improve the `llm_canary` detector. The current canary is intentionally simple and brittle: it expects an exact `ok`, does not satisfy every adversarial fixture in live-model testing, and needs a stronger prompt, timeout/retry policy, calibrated model choice, and better false-positive/false-negative measurement. AI would help compare prompt variants against the sanitized fixture set and summarize failure patterns without ingesting the original Appendix wholesale.
- Add CI that runs tests, TypeScript build, and gitleaks on every push. AI would help write and review the GitHub Actions workflow.

## First AI Interaction

Tool: ChatGPT/Codex.

Verbatim first prompt sent:

> [Sanitized_Task.txt](Sanitized_Task.txt) This is the description of the task we've been given. I have an idea for an implementation I'd like to perform. Do note the section mentioning Prompt.md before doing anything else.

Handling note: I did not paste the original unsanitized Appendix A corpus into the AI session. The repo contained only `Sanitized_Task.txt`; Appendix cases are intended to be inserted manually into `test/fixtures/adversarial-cases.json` after review.
