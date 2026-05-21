# AI Process Log

## Tools Used

- ChatGPT/Codex: planning, repository inspection, implementation, tests, and documentation.
- Second AI tool: planned security review/debugging pass before final submission. Fill this section with the exact tool name and prompts after that pass, so the document remains honest.

## Why Multiple Tools

The intended workflow is to use ChatGPT/Codex for the first implementation pass, then use a second AI tool to challenge the security controls and tests on the same solution files, especially `src/security/injectionDetector.ts`, `src/security/piiRedactor.ts`, and `src/security/outputValidator.ts`.

Update this section after the second pass with the exact files touched and what was accepted or rejected.

## Three Example Prompts

### Code Generation

Verbatim prompt:

> PLEASE IMPLEMENT THIS PLAN:
> # SecureLLM Gateway Plan
> ...

What I did with the output: used it to generate the initial TypeScript/Express service, security modules, tests, Docker files, README, and this process document.

### Security Review

Verbatim prompt to add after second-tool review:

> TODO: paste the exact second-tool security-review prompt here before submission.

What I did with the output: TODO.

### Debugging

Verbatim prompt to add after debugging:

> TODO: paste the exact debugging prompt here before submission.

What I did with the output: TODO.

## What I Rejected

TODO before submission: record one concrete AI suggestion that was rejected or rewritten and why. A likely example is rejecting storage or logging of raw PII in audit records, because audit records should store encrypted token mappings and hashes rather than raw request/response bodies.

## What I Would Do With More Time

- Add a larger adversarial corpus from Appendix A and mutation tests for realistic spacing, casing, delimiter, and homoglyph variations. AI would help generate variants after the original cases are manually placed in local fixtures.
- Add CI that runs tests, TypeScript build, and gitleaks against git history. AI would help write and review the GitHub Actions workflow.

## First AI Interaction

Tool: ChatGPT/Codex.

Verbatim first prompt sent:

> [Sanitized_Task.txt](Sanitized_Task.txt) This is the description of the task we've been given. I have an idea for an implementation I'd like to perform. Do note the section mentioning Prompt.md before doing anything else.

Handling note: I did not paste the original unsanitized Appendix A corpus into the AI session. The repo contained only `Sanitized_Task.txt`; Appendix cases are intended to be inserted manually into `test/fixtures/adversarial-cases.json` after review.
