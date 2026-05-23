import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, relative } from "node:path";

type AssertionResult = {
  ancestorTitles?: string[];
  fullName?: string;
  title?: string;
  status?: string;
  duration?: number;
  failureMessages?: string[];
};

type FileResult = {
  name?: string;
  testFilePath?: string;
  status?: string;
  startTime?: number;
  endTime?: number;
  assertionResults?: AssertionResult[];
  message?: string;
};

type VitestJson = {
  success?: boolean;
  numTotalTests?: number;
  numPassedTests?: number;
  numFailedTests?: number;
  numPendingTests?: number;
  numTodoTests?: number;
  startTime?: number;
  testResults?: FileResult[];
};

type CanaryTrace = {
  testName: string;
  mode: "unit" | "route" | string;
  usesLiveLlm: boolean;
  canaryInput: unknown;
  canaryOutput?: string;
  expectedResult: string;
};

const inputPath = process.argv[2] ?? "test-results.json";
const outputPath = process.argv[3] ?? "test-results.html";
const liveCanaryTracePath = process.argv[4] ?? ".test-artifacts/live-canary-traces.json";
const report = JSON.parse(readFileSync(inputPath, "utf8")) as VitestJson;
const files = report.testResults ?? [];
const liveCanaryTraces = existsSync(liveCanaryTracePath)
  ? (JSON.parse(readFileSync(liveCanaryTracePath, "utf8")) as CanaryTrace[])
  : [];
const canaryTraceByName = new Map(liveCanaryTraces.map((trace) => [trace.testName, trace]));

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function statusClass(status: string | undefined): string {
  if (status === "passed") return "passed";
  if (status === "failed") return "failed";
  if (status === "pending" || status === "todo" || status === "skipped") return "skipped";
  return "unknown";
}

function durationMs(value: number | undefined): string {
  if (typeof value !== "number" || Number.isNaN(value)) return "";
  return `${Math.round(value)} ms`;
}

function fileDuration(file: FileResult): string {
  if (typeof file.startTime === "number" && typeof file.endTime === "number") {
    return durationMs(file.endTime - file.startTime);
  }
  const total = file.assertionResults?.reduce((sum, test) => sum + (test.duration ?? 0), 0);
  return durationMs(total);
}

function displayPath(file: FileResult): string {
  const path = file.name ?? file.testFilePath ?? "unknown";
  try {
    return relative(process.cwd(), path) || basename(path);
  } catch {
    return path;
  }
}

const total = report.numTotalTests ?? files.reduce((sum, file) => sum + (file.assertionResults?.length ?? 0), 0);
const passed = report.numPassedTests ?? files.flatMap((file) => file.assertionResults ?? []).filter((test) => test.status === "passed").length;
const failed = report.numFailedTests ?? files.flatMap((file) => file.assertionResults ?? []).filter((test) => test.status === "failed").length;
const skipped =
  (report.numPendingTests ?? 0) +
  (report.numTodoTests ?? 0) +
  files.flatMap((file) => file.assertionResults ?? []).filter((test) => ["skipped", "pending", "todo"].includes(test.status ?? "")).length;
const generatedAt = new Date().toISOString();

const fileRows = files
  .map((file) => {
    const assertions = file.assertionResults ?? [];
    const filePassed = assertions.filter((test) => test.status === "passed").length;
    const fileFailed = assertions.filter((test) => test.status === "failed").length;
    return `<tr>
      <td><span class="pill ${statusClass(file.status)}">${escapeHtml(file.status ?? "unknown")}</span></td>
      <td>${escapeHtml(displayPath(file))}</td>
      <td>${assertions.length}</td>
      <td>${filePassed}</td>
      <td>${fileFailed}</td>
      <td>${escapeHtml(fileDuration(file))}</td>
    </tr>`;
  })
  .join("\n");

const testRows = files
  .flatMap((file) =>
    (file.assertionResults ?? []).map((test) => {
      const name = test.fullName ?? [...(test.ancestorTitles ?? []), test.title].filter(Boolean).join(" > ");
      const failures = (test.failureMessages ?? []).join("\n\n");
      const canaryTrace = canaryTraceByName.get(name);
      return `<tr>
        <td><span class="pill ${statusClass(test.status)}">${escapeHtml(test.status ?? "unknown")}</span></td>
        <td>${escapeHtml(displayPath(file))}</td>
        <td>${escapeHtml(name)}${canaryTrace ? renderCanaryTrace(canaryTrace) : ""}</td>
        <td>${escapeHtml(durationMs(test.duration))}</td>
        <td>${failures ? `<pre>${escapeHtml(failures)}</pre>` : ""}</td>
      </tr>`;
    })
  )
  .join("\n");

function renderCanaryTrace(trace: CanaryTrace): string {
  return `<details class="canary-trace">
    <summary>Canary trace (${escapeHtml(trace.mode)}, ${trace.usesLiveLlm ? "live LLM" : "mocked LLM"})</summary>
    <div class="trace-grid">
      <div><strong>Input</strong><pre>${escapeHtml(JSON.stringify(trace.canaryInput, null, 2))}</pre></div>
      <div><strong>Output</strong><pre>${escapeHtml(trace.canaryOutput ?? "")}</pre></div>
      <div><strong>Expected</strong><pre>${escapeHtml(trace.expectedResult)}</pre></div>
    </div>
  </details>`;
}

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SecureLLM Gateway Test Report</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #f7f7f5;
      --fg: #202124;
      --muted: #60646c;
      --panel: #ffffff;
      --border: #d8dadd;
      --pass: #0f7b3f;
      --fail: #b42318;
      --skip: #8a6116;
    }
    body {
      margin: 0;
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--fg);
    }
    main {
      max-width: 1200px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }
    h1, h2 {
      margin: 0 0 12px;
      line-height: 1.2;
    }
    h2 {
      margin-top: 28px;
    }
    .meta {
      color: var(--muted);
      margin-bottom: 20px;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin: 20px 0 28px;
    }
    .metric {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
    }
    .metric .label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    .metric .value {
      font-size: 28px;
      font-weight: 700;
      margin-top: 4px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .04em;
      background: color-mix(in srgb, var(--panel), var(--border) 22%);
    }
    tr:last-child td {
      border-bottom: 0;
    }
    .pill {
      display: inline-block;
      min-width: 58px;
      border-radius: 999px;
      padding: 2px 8px;
      color: #fff;
      font-size: 12px;
      text-align: center;
      font-weight: 650;
    }
    .passed { background: var(--pass); }
    .failed { background: var(--fail); }
    .skipped, .unknown { background: var(--skip); }
    pre {
      margin: 0;
      white-space: pre-wrap;
      max-width: 560px;
      font-size: 12px;
      color: var(--fail);
    }
    .canary-trace {
      margin-top: 8px;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px;
      background: color-mix(in srgb, var(--panel), var(--border) 12%);
    }
    .canary-trace summary {
      cursor: pointer;
      color: var(--muted);
      font-weight: 650;
    }
    .trace-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
      margin-top: 8px;
    }
    .canary-trace pre {
      color: var(--fg);
      max-width: none;
      margin-top: 4px;
      padding: 8px;
      border-radius: 6px;
      background: color-mix(in srgb, var(--panel), var(--bg) 55%);
      overflow: auto;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #111214;
        --fg: #f1f3f4;
        --muted: #a9adb5;
        --panel: #1b1d21;
        --border: #343842;
      }
    }
  </style>
</head>
<body>
  <main>
    <h1>SecureLLM Gateway Test Report</h1>
    <div class="meta">Generated ${escapeHtml(generatedAt)} from ${escapeHtml(inputPath)}</div>
    <div class="meta">Canary test traces are loaded from ${escapeHtml(liveCanaryTracePath)} when present. Live integration tests use the configured LLM provider.</div>
    <section class="summary">
      <div class="metric"><div class="label">Status</div><div class="value">${report.success ? "Passed" : "Failed"}</div></div>
      <div class="metric"><div class="label">Total</div><div class="value">${total}</div></div>
      <div class="metric"><div class="label">Passed</div><div class="value">${passed}</div></div>
      <div class="metric"><div class="label">Failed</div><div class="value">${failed}</div></div>
      <div class="metric"><div class="label">Skipped</div><div class="value">${skipped}</div></div>
    </section>
    <h2>Files</h2>
    <table>
      <thead><tr><th>Status</th><th>File</th><th>Tests</th><th>Passed</th><th>Failed</th><th>Duration</th></tr></thead>
      <tbody>${fileRows}</tbody>
    </table>
    <h2>Tests</h2>
    <table>
      <thead><tr><th>Status</th><th>File</th><th>Test</th><th>Duration</th><th>Failure</th></tr></thead>
      <tbody>${testRows}</tbody>
    </table>
  </main>
</body>
</html>
`;

writeFileSync(outputPath, html);
console.log(`Wrote ${outputPath}`);
