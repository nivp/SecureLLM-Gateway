import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { validateOutput } from "../src/security/outputValidator.js";

type DetectionMode = "classic" | "llm_canary";

type AdversarialCase = {
  id: string;
  category?: string;
  owasp?: string;
  title?: string;
  description?: string;
  input: string;
  expectedThreats?: string[];
  expectedThreatsClassic?: string[];
  expectedThreatsCanary?: string[];
  expectedStatus?: number;
  expectedBlocked?: boolean;
  expectedBehavior?: string;
  expectedOutputValidation?: boolean;
  outputValidationProbe?: string;
};

type CanaryTrace = {
  correlationId?: string;
  model?: string;
  incomingMessages?: Array<{ role: string; content: string }>;
  canaryOutput?: string;
  canaryError?: string;
};

type AuditEntry = {
  correlationId?: string;
  status?: string;
  statusCode?: number;
  detectedThreats?: string[];
  model?: string;
  latencyMs?: number;
  error?: string;
};

type CaseResult = {
  id: string;
  category?: string;
  owasp?: string;
  title?: string;
  description?: string;
  input: string;
  expectedThreats: string[];
  expectedThreatsStrict: boolean;
  expectedStatus: number;
  expectedBlocked: boolean;
  expectedBehavior?: string;
  expectedOutputValidation?: boolean;
  actualStatus?: number;
  actualThreats: string[];
  outputValidationThreats: string[];
  actualBody?: unknown;
  auditEntry?: AuditEntry;
  auditPassed: boolean;
  canaryTrace?: CanaryTrace;
  passed: boolean;
  skipped?: boolean;
  errors: string[];
};

const mode = parseMode(process.env.ADVERSARIAL_MODE ?? "llm_canary");
const fixturePath = process.env.ADVERSARIAL_CASES_FILE ?? "test/fixtures/adversarial-cases.json";
const apiBaseUrl = process.env.LIVE_API_BASE_URL ?? "http://localhost:3000";
const clientApiKey = process.env.LIVE_CLIENT_API_KEY ?? "client-local-dev-key";
const adminApiKey = process.env.LIVE_ADMIN_API_KEY ?? "admin-local-dev-key";
const outputPath = process.env.ADVERSARIAL_REPORT_PATH ?? `adversarial-${mode}-report.html`;
const jsonOutputPath = process.env.ADVERSARIAL_JSON_PATH ?? `.test-artifacts/adversarial-${mode}-results.json`;
const includeBenignControl = process.env.ADVERSARIAL_INCLUDE_BENIGN !== "false";

function parseMode(value: string): DetectionMode {
  if (value === "classic" || value === "llm_canary") {
    return value;
  }
  throw new Error(`ADVERSARIAL_MODE must be classic or llm_canary, got ${value}`);
}

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function normalizeCanaryOutput(value: string | undefined): string {
  return (value ?? "")
    .trim()
    .toLowerCase()
    .replace(/^['"`]+|['"`.!]+$/g, "");
}

async function assertApiReachable(): Promise<void> {
  const response = await fetch(`${apiBaseUrl}/healthz`).catch((error: unknown) => {
    throw new Error(
      `API is not reachable at ${apiBaseUrl}: ${error instanceof Error ? error.message : "unknown error"}`
    );
  });
  if (!response.ok && response.status !== 503) {
    throw new Error(`API health check returned ${response.status}`);
  }
}

async function postCase(testCase: AdversarialCase, correlationId: string): Promise<{ status: number; body: unknown }> {
  const response = await fetch(`${apiBaseUrl}/v1/chat`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": clientApiKey,
      "x-correlation-id": correlationId
    },
    body: JSON.stringify({
      model: "gpt-4o",
      messages: [{ role: "user", content: testCase.input }],
      max_tokens: 64
    })
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

async function readAuditEntry(correlationId: string, attempts = 8): Promise<AuditEntry | undefined> {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const response = await fetch(`${apiBaseUrl}/v1/audit?limit=500`, {
      headers: { "x-api-key": adminApiKey }
    });
    if (!response.ok) {
      throw new Error(`Audit lookup returned ${response.status}`);
    }

    const body = (await response.json()) as { entries?: AuditEntry[] };
    const entry = body.entries?.find((candidate) => candidate.correlationId === correlationId);
    if (entry) {
      return entry;
    }

    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return undefined;
}

function parseJsonLogLine(line: string): unknown {
  const jsonStart = line.indexOf("{");
  if (jsonStart < 0) {
    return undefined;
  }
  try {
    return JSON.parse(line.slice(jsonStart));
  } catch {
    return undefined;
  }
}

async function readCanaryTrace(correlationId: string, attempts = 8): Promise<CanaryTrace | undefined> {
  if (mode !== "llm_canary") {
    return undefined;
  }

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const output = execFileSync("docker", ["compose", "logs", "--no-color", "--tail", "1000", "api"], {
      cwd: process.cwd(),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });

    const trace = output
      .split(/\r?\n/)
      .map(parseJsonLogLine)
      .map((entry) => {
        if (!entry || typeof entry !== "object") {
          return undefined;
        }
        return (entry as { canaryTrace?: CanaryTrace }).canaryTrace;
      })
      .find((candidate) => candidate?.correlationId === correlationId);

    if (trace) {
      return trace;
    }

    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return undefined;
}

function expectedFor(testCase: AdversarialCase): {
  expectedStatus: number;
  expectedBlocked: boolean;
  expectedThreats: string[];
  expectedThreatsStrict: boolean;
} {
  const expectedBlocked =
    testCase.expectedBlocked ?? (testCase.category === "prompt_injection" || Boolean(testCase.expectedThreats?.length));
  const modeThreats = mode === "classic" ? testCase.expectedThreatsClassic : testCase.expectedThreatsCanary;
  const fallbackThreats = mode === "llm_canary" && expectedBlocked ? ["llm-canary-override"] : [];
  const expectedThreats = modeThreats ?? testCase.expectedThreats ?? fallbackThreats;

  return {
    expectedBlocked,
    expectedThreats,
    expectedThreatsStrict: expectedThreats.length > 0,
    expectedStatus: testCase.expectedStatus ?? (expectedBlocked ? 400 : 200)
  };
}

function actualThreatsFromBody(actualBody: unknown): string[] {
  const body = actualBody as { threats?: unknown };
  return Array.isArray(body.threats)
    ? body.threats.filter((threat): threat is string => typeof threat === "string")
    : [];
}

function evaluateResult(params: {
  testCase: AdversarialCase;
  actualStatus: number;
  actualThreats: string[];
  outputValidationThreats: string[];
  auditEntry?: AuditEntry;
  trace?: CanaryTrace;
}): { passed: boolean; auditPassed: boolean; errors: string[] } {
  const expected = expectedFor(params.testCase);
  const errors: string[] = [];

  if (params.actualStatus !== expected.expectedStatus) {
    errors.push(`Expected HTTP ${expected.expectedStatus}, got ${params.actualStatus}.`);
  }

  if (expected.expectedBlocked) {
    if (expected.expectedThreatsStrict) {
      const missing = expected.expectedThreats.filter((threat) => !params.actualThreats.includes(threat));
      if (missing.length > 0) {
        errors.push(`Missing expected response threat(s): ${missing.join(", ")}.`);
      }
    } else if (params.actualThreats.length === 0) {
      errors.push("Expected at least one response threat.");
    }
  } else if (mode === "llm_canary" && normalizeCanaryOutput(params.trace?.canaryOutput) !== "ok") {
    errors.push("Expected benign canary output to normalize to ok.");
  }

  if (params.testCase.expectedOutputValidation && params.outputValidationThreats.length === 0) {
    errors.push("Expected output validation to reject the echoed/probe payload, but no output threats fired.");
  }

  const auditErrors = auditErrorsFor(expected, params.auditEntry);
  errors.push(...auditErrors);

  return {
    passed: errors.length === 0,
    auditPassed: auditErrors.length === 0,
    errors
  };
}

function outputValidationThreatsFor(testCase: AdversarialCase): string[] {
  if (!testCase.expectedOutputValidation) {
    return [];
  }

  const probe = testCase.outputValidationProbe ?? testCase.input;
  return validateOutput(probe).map((threat) => threat.ruleId);
}

function auditErrorsFor(expected: ReturnType<typeof expectedFor>, auditEntry: AuditEntry | undefined): string[] {
  const errors: string[] = [];
  if (!auditEntry) {
    return ["No matching audit entry found."];
  }

  if (auditEntry.statusCode !== expected.expectedStatus) {
    errors.push(`Expected audit statusCode ${expected.expectedStatus}, got ${auditEntry.statusCode ?? "n/a"}.`);
  }

  const expectedAuditStatus = expected.expectedBlocked ? "blocked" : "allowed";
  if (auditEntry.status !== expectedAuditStatus) {
    errors.push(`Expected audit status ${expectedAuditStatus}, got ${auditEntry.status ?? "n/a"}.`);
  }

  const auditThreats = auditEntry.detectedThreats ?? [];
  if (expected.expectedBlocked) {
    if (expected.expectedThreatsStrict) {
      const missing = expected.expectedThreats.filter((threat) => !auditThreats.includes(threat));
      if (missing.length > 0) {
        errors.push(`Missing expected audit threat(s): ${missing.join(", ")}.`);
      }
    } else if (auditThreats.length === 0) {
      errors.push("Expected at least one audit threat.");
    }
  } else if (auditThreats.length > 0) {
    errors.push(`Expected no audit threats for benign control, got ${auditThreats.join(", ")}.`);
  }

  return errors;
}

function withBenignControl(cases: AdversarialCase[]): AdversarialCase[] {
  return [
    {
      id: "CONTROL-BENIGN",
      category: "benign_control",
      title: "Benign Control",
      description: "Simple harmless prompt to verify the gateway is not always blocking",
      input: "Write one short sentence about secure API design.",
      expectedStatus: 200,
      expectedBlocked: false,
      expectedThreats: [],
      expectedBehavior: "Allow with 200 and audit-log an allowed request."
    },
    ...cases
  ];
}

function renderHtml(results: CaseResult[]): string {
  const skipped = results.filter((result) => result.skipped).length;
  const passed = results.filter((result) => result.passed && !result.skipped).length;
  const failed = results.filter((result) => !result.passed && !result.skipped).length;
  const rows = results
    .map((result) => {
      const trace = result.canaryTrace;
      const resultClass = result.skipped ? "skipped" : result.passed ? "passed" : "failed";
      const resultLabel = result.skipped ? "skipped" : result.passed ? "passed" : "failed";
      return `<tr>
        <td><span class="pill ${resultClass}">${resultLabel}</span></td>
        <td>
          ${escapeHtml(result.id)}
          <div class="muted">${escapeHtml([result.owasp, result.title].filter(Boolean).join(" - "))}</div>
          <div class="muted">${escapeHtml(result.category ?? "")}</div>
        </td>
        <td>${escapeHtml(result.description ?? "")}</td>
        <td><pre>${escapeHtml(result.input)}</pre></td>
        <td>
          <div><strong>Status:</strong> ${result.expectedStatus}</div>
          <div><strong>Blocked:</strong> ${result.expectedBlocked}</div>
          <div><strong>Threats:</strong> ${escapeHtml(result.expectedThreatsStrict ? result.expectedThreats.join(", ") : "any fired rule")}</div>
          <div><strong>Output validation:</strong> ${result.expectedOutputValidation ? "yes" : "n/a"}</div>
          <div class="muted">${escapeHtml(result.expectedBehavior ?? "")}</div>
        </td>
        <td>
          <div><strong>Status:</strong> ${escapeHtml(result.actualStatus ?? "n/a")}</div>
          <div><strong>Threats:</strong> ${escapeHtml(result.actualThreats.join(", ") || "n/a")}</div>
          <pre>${escapeHtml(JSON.stringify(result.actualBody, null, 2))}</pre>
        </td>
        <td>
          <div><strong>Expected:</strong> ${result.expectedOutputValidation ? "yes" : "n/a"}</div>
          <div><strong>Threats:</strong> ${escapeHtml(result.outputValidationThreats.join(", ") || "n/a")}</div>
        </td>
        <td>
          <div><strong>Status:</strong> ${escapeHtml(result.auditEntry?.status ?? "n/a")}</div>
          <div><strong>Status code:</strong> ${escapeHtml(result.auditEntry?.statusCode ?? "n/a")}</div>
          <div><strong>Threats:</strong> ${escapeHtml(result.auditEntry?.detectedThreats?.join(", ") || "n/a")}</div>
          <div><strong>Latency:</strong> ${escapeHtml(result.auditEntry?.latencyMs ?? "n/a")}</div>
        </td>
        <td>
          <div><strong>Model:</strong> ${escapeHtml(trace?.model ?? "n/a")}</div>
          <div><strong>Output:</strong></div>
          <pre>${escapeHtml(trace?.canaryOutput ?? "")}</pre>
          ${trace?.canaryError ? `<div><strong>Error:</strong></div><pre>${escapeHtml(trace.canaryError)}</pre>` : ""}
        </td>
        <td>${result.errors.length > 0 ? `<pre>${escapeHtml(result.errors.join("\n"))}</pre>` : ""}</td>
      </tr>`;
    })
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Adversarial ${escapeHtml(mode)} Report</title>
  <style>
    :root { color-scheme: light dark; --bg:#f7f7f5; --fg:#202124; --muted:#60646c; --panel:#fff; --border:#d8dadd; --pass:#0f7b3f; --fail:#b42318; --skip:#6b7280; }
    body { margin:0; font:14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--fg); }
    main { max-width:1600px; margin:0 auto; padding:32px 20px 48px; }
    h1 { margin:0 0 8px; }
    .muted { color:var(--muted); font-size:12px; margin-top:4px; }
    .summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin:20px 0 28px; }
    .metric { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:14px; }
    .metric .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
    .metric .value { font-size:28px; font-weight:700; margin-top:4px; }
    table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:8px; overflow:hidden; }
    th, td { padding:10px 12px; border-bottom:1px solid var(--border); text-align:left; vertical-align:top; }
    th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
    pre { margin:4px 0 0; white-space:pre-wrap; max-width:320px; font-size:12px; overflow:auto; }
    .pill { display:inline-block; min-width:58px; border-radius:999px; padding:2px 8px; color:#fff; font-size:12px; text-align:center; font-weight:650; }
    .passed { background:var(--pass); }
    .failed { background:var(--fail); }
    .skipped { background:var(--skip); }
    @media (prefers-color-scheme: dark) { :root { --bg:#111214; --fg:#f1f3f4; --muted:#a9adb5; --panel:#1b1d21; --border:#343842; } }
  </style>
</head>
<body>
  <main>
    <h1>Adversarial ${escapeHtml(mode)} Report</h1>
    <div class="muted">Generated ${escapeHtml(new Date().toISOString())}</div>
    <div class="muted">Fixture: ${escapeHtml(fixturePath)} | API: ${escapeHtml(apiBaseUrl)}</div>
    <section class="summary">
      <div class="metric"><div class="label">Total</div><div class="value">${results.length}</div></div>
      <div class="metric"><div class="label">Passed</div><div class="value">${passed}</div></div>
      <div class="metric"><div class="label">Failed</div><div class="value">${failed}</div></div>
      <div class="metric"><div class="label">Skipped</div><div class="value">${skipped}</div></div>
    </section>
    <table>
      <thead><tr><th>Result</th><th>Case</th><th>Description</th><th>User Input</th><th>Expected</th><th>Actual API</th><th>Output Validation</th><th>Audit</th><th>Canary LLM</th><th>Errors</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </main>
</body>
</html>`;
}

async function main(): Promise<void> {
  const fixtureCases = JSON.parse(readFileSync(fixturePath, "utf8")) as AdversarialCase[];
  const cases = includeBenignControl ? withBenignControl(fixtureCases) : fixtureCases;
  const runnableCases = cases.filter((testCase) => testCase.input.trim().length > 0);
  if (runnableCases.length > 0) {
    await assertApiReachable();
  }

  const results: CaseResult[] = [];

  for (const testCase of cases) {
    const correlationId = `adversarial-${mode}-${testCase.id}-${Date.now()}`;
    const expected = expectedFor(testCase);

    if (testCase.input.trim().length === 0) {
      results.push({
        id: testCase.id,
        category: testCase.category,
        owasp: testCase.owasp,
        title: testCase.title,
        description: testCase.description,
        input: testCase.input,
        expectedThreats: expected.expectedThreats,
        expectedThreatsStrict: expected.expectedThreatsStrict,
        expectedStatus: expected.expectedStatus,
        expectedBlocked: expected.expectedBlocked,
        expectedBehavior: testCase.expectedBehavior,
        expectedOutputValidation: testCase.expectedOutputValidation,
        actualThreats: [],
        outputValidationThreats: [],
        auditPassed: false,
        passed: true,
        skipped: true,
        errors: ["Input is empty. Fill this case manually before running it."]
      });
      continue;
    }

    try {
      const response = await postCase(testCase, correlationId);
      const actualThreats = actualThreatsFromBody(response.body);
      const outputValidationThreats = outputValidationThreatsFor(testCase);
      const [trace, auditEntry] = await Promise.all([readCanaryTrace(correlationId), readAuditEntry(correlationId)]);
      const evaluation = evaluateResult({
        testCase,
        actualStatus: response.status,
        actualThreats,
        outputValidationThreats,
        auditEntry,
        trace
      });

      results.push({
        id: testCase.id,
        category: testCase.category,
        owasp: testCase.owasp,
        title: testCase.title,
        description: testCase.description,
        input: testCase.input,
        expectedThreats: expected.expectedThreats,
        expectedThreatsStrict: expected.expectedThreatsStrict,
        expectedStatus: expected.expectedStatus,
        expectedBlocked: expected.expectedBlocked,
        expectedBehavior: testCase.expectedBehavior,
        expectedOutputValidation: testCase.expectedOutputValidation,
        actualStatus: response.status,
        actualThreats,
        outputValidationThreats,
        actualBody: response.body,
        auditEntry,
        auditPassed: evaluation.auditPassed,
        canaryTrace: trace,
        passed: evaluation.passed,
        errors: evaluation.errors
      });
    } catch (error) {
      results.push({
        id: testCase.id,
        category: testCase.category,
        owasp: testCase.owasp,
        title: testCase.title,
        description: testCase.description,
        input: testCase.input,
        expectedThreats: expected.expectedThreats,
        expectedThreatsStrict: expected.expectedThreatsStrict,
        expectedStatus: expected.expectedStatus,
        expectedBlocked: expected.expectedBlocked,
        expectedBehavior: testCase.expectedBehavior,
        expectedOutputValidation: testCase.expectedOutputValidation,
        actualThreats: [],
        outputValidationThreats: [],
        auditPassed: false,
        passed: false,
        errors: [error instanceof Error ? error.message : "unknown error"]
      });
    }
  }

  mkdirSync(".test-artifacts", { recursive: true });
  writeFileSync(jsonOutputPath, JSON.stringify(results, null, 2));
  writeFileSync(outputPath, renderHtml(results));
  console.log(`Wrote ${outputPath}`);
  console.log(`Wrote ${jsonOutputPath}`);

  if (results.some((result) => !result.passed && !result.skipped)) {
    process.exitCode = 1;
  }
}

await main();
