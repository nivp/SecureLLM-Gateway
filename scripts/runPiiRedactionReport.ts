import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { redactMessages } from "../src/security/piiRedactor.js";
import type { RedactionToken } from "../src/types.js";

type PiiCase = {
  id: string;
  category?: string;
  title?: string;
  description?: string;
  input: string;
  expectedValues: string[];
  expectedCategories: RedactionToken["category"][];
  expectedBehavior?: string;
};

type CaseResult = {
  id: string;
  category?: string;
  title?: string;
  description?: string;
  input: string;
  redactedInput: string;
  expectedValues: string[];
  expectedCategories: RedactionToken["category"][];
  expectedBehavior?: string;
  tokens: RedactionToken[];
  passed: boolean;
  errors: string[];
};

const fixturePath = process.env.PII_CASES_FILE ?? "test/fixtures/pii-cases.json";
const outputPath = process.env.PII_REPORT_PATH ?? "pii-redaction-report.html";
const jsonOutputPath = process.env.PII_JSON_PATH ?? ".test-artifacts/pii-redaction-results.json";

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function missingCategories(
  expected: RedactionToken["category"][],
  actual: RedactionToken["category"][]
): RedactionToken["category"][] {
  const remaining = [...actual];
  return expected.filter((category) => {
    const index = remaining.indexOf(category);
    if (index < 0) {
      return true;
    }
    remaining.splice(index, 1);
    return false;
  });
}

function evaluate(testCase: PiiCase): CaseResult {
  const redacted = redactMessages([{ role: "user", content: testCase.input }]);
  const redactedInput = redacted.messages[0]?.content ?? "";
  const tokenValues = redacted.tokens.map((token) => token.value);
  const tokenCategories = redacted.tokens.map((token) => token.category);
  const errors: string[] = [];

  for (const value of testCase.expectedValues) {
    if (redactedInput.includes(value)) {
      errors.push(`Raw PII value was still present after redaction: ${value}`);
    }
    if (!tokenValues.includes(value)) {
      errors.push(`Expected token metadata for raw PII value: ${value}`);
    }
  }

  const missing = missingCategories(testCase.expectedCategories, tokenCategories);
  if (missing.length > 0) {
    errors.push(`Missing expected category token(s): ${missing.join(", ")}`);
  }

  if (redacted.tokens.length < testCase.expectedValues.length) {
    errors.push(
      `Expected at least ${testCase.expectedValues.length} redaction token(s), got ${redacted.tokens.length}.`
    );
  }

  return {
    id: testCase.id,
    category: testCase.category,
    title: testCase.title,
    description: testCase.description,
    input: testCase.input,
    redactedInput,
    expectedValues: testCase.expectedValues,
    expectedCategories: testCase.expectedCategories,
    expectedBehavior: testCase.expectedBehavior,
    tokens: redacted.tokens,
    passed: errors.length === 0,
    errors
  };
}

function renderTokens(tokens: RedactionToken[]): string {
  if (tokens.length === 0) {
    return "";
  }

  return `<table class="nested">
    <thead><tr><th>Token</th><th>Category</th><th>Original Value</th></tr></thead>
    <tbody>${tokens
      .map(
        (token) =>
          `<tr><td>${escapeHtml(token.token)}</td><td>${escapeHtml(token.category)}</td><td><code>${escapeHtml(token.value)}</code></td></tr>`
      )
      .join("\n")}</tbody>
  </table>`;
}

function renderHtml(results: CaseResult[]): string {
  const passed = results.filter((result) => result.passed).length;
  const failed = results.length - passed;
  const rows = results
    .map((result) => {
      const resultClass = result.passed ? "passed" : "failed";
      return `<tr>
        <td><span class="pill ${resultClass}">${result.passed ? "passed" : "failed"}</span></td>
        <td>
          ${escapeHtml(result.id)}
          <div class="muted">${escapeHtml(result.title ?? "")}</div>
          <div class="muted">${escapeHtml(result.category ?? "")}</div>
        </td>
        <td>
          ${escapeHtml(result.description ?? "")}
          <div class="muted">${escapeHtml(result.expectedBehavior ?? "")}</div>
        </td>
        <td><pre>${escapeHtml(result.input)}</pre></td>
        <td><pre>${escapeHtml(result.redactedInput)}</pre></td>
        <td>${renderTokens(result.tokens)}</td>
        <td>
          <div><strong>Values:</strong> ${escapeHtml(result.expectedValues.join(", "))}</div>
          <div><strong>Categories:</strong> ${escapeHtml(result.expectedCategories.join(", "))}</div>
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
  <title>PII Redaction Report</title>
  <style>
    :root { color-scheme: light dark; --bg:#f7f7f5; --fg:#202124; --muted:#60646c; --panel:#fff; --border:#d8dadd; --pass:#0f7b3f; --fail:#b42318; }
    body { margin:0; font:14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--fg); }
    main { max-width:1500px; margin:0 auto; padding:32px 20px 48px; }
    h1 { margin:0 0 8px; }
    .muted { color:var(--muted); font-size:12px; margin-top:4px; }
    .summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin:20px 0 28px; }
    .metric { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:14px; }
    .metric .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
    .metric .value { font-size:28px; font-weight:700; margin-top:4px; }
    table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:8px; overflow:hidden; }
    th, td { padding:10px 12px; border-bottom:1px solid var(--border); text-align:left; vertical-align:top; }
    th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
    pre { margin:4px 0 0; white-space:pre-wrap; max-width:360px; font-size:12px; overflow:auto; }
    code { font:12px ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; }
    .pill { display:inline-block; min-width:58px; border-radius:999px; padding:2px 8px; color:#fff; font-size:12px; text-align:center; font-weight:650; }
    .passed { background:var(--pass); }
    .failed { background:var(--fail); }
    .nested { border-radius:0; font-size:12px; }
    .nested th, .nested td { padding:6px 8px; }
    @media (prefers-color-scheme: dark) { :root { --bg:#111214; --fg:#f1f3f4; --muted:#a9adb5; --panel:#1b1d21; --border:#343842; } }
  </style>
</head>
<body>
  <main>
    <h1>PII Redaction Report</h1>
    <div class="muted">Generated ${escapeHtml(new Date().toISOString())}</div>
    <div class="muted">Fixture: ${escapeHtml(fixturePath)}</div>
    <section class="summary">
      <div class="metric"><div class="label">Total</div><div class="value">${results.length}</div></div>
      <div class="metric"><div class="label">Passed</div><div class="value">${passed}</div></div>
      <div class="metric"><div class="label">Failed</div><div class="value">${failed}</div></div>
    </section>
    <table>
      <thead><tr><th>Result</th><th>Case</th><th>Description</th><th>Original Prompt</th><th>Forwarded Prompt</th><th>Tokens</th><th>Expected</th><th>Errors</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </main>
</body>
</html>`;
}

const cases = JSON.parse(readFileSync(fixturePath, "utf8")) as PiiCase[];
const results = cases.map(evaluate);

mkdirSync(".test-artifacts", { recursive: true });
writeFileSync(jsonOutputPath, JSON.stringify(results, null, 2));
writeFileSync(outputPath, renderHtml(results));
console.log(`Wrote ${outputPath}`);
console.log(`Wrote ${jsonOutputPath}`);

if (results.some((result) => !result.passed)) {
  process.exitCode = 1;
}
