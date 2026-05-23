param(
  [string]$ApiBaseUrl = "http://localhost:3000",
  [string]$ClientApiKey = "client-local-dev-key",
  [string]$AdminApiKey = "admin-local-dev-key",
  [string]$Model = "gpt-oss:20b",
  [string]$CasesFile = "test/fixtures/adversarial-cases.json",
  [string]$ReportPath = "adversarial-canary-report.html",
  [switch]$SkipPull,
  [switch]$NoBuild
)

$ErrorActionPreference = "Stop"

function Invoke-Step {
  param(
    [string]$Name,
    [scriptblock]$Command
  )

  Write-Host ""
  Write-Host "==> $Name" -ForegroundColor Cyan
  & $Command
  if ($LASTEXITCODE -ne 0) {
    throw "Step failed with exit code $LASTEXITCODE`: $Name"
  }
}

$previousDebugLogs = [Environment]::GetEnvironmentVariable("LLM_CANARY_DEBUG_LOGS", "Process")
$previousApiBaseUrl = [Environment]::GetEnvironmentVariable("LIVE_API_BASE_URL", "Process")
$previousClientKey = [Environment]::GetEnvironmentVariable("LIVE_CLIENT_API_KEY", "Process")
$previousCases = [Environment]::GetEnvironmentVariable("ADVERSARIAL_CASES_FILE", "Process")
$previousReport = [Environment]::GetEnvironmentVariable("ADVERSARIAL_REPORT_PATH", "Process")
$previousCanaryModel = [Environment]::GetEnvironmentVariable("OPENAI_CANARY_MODEL", "Process")

try {
  $env:LLM_CANARY_DEBUG_LOGS = "true"
  $env:OPENAI_CANARY_MODEL = $Model

  Invoke-Step "Starting Docker Compose stack with canary debug logs" {
    if ($NoBuild) {
      docker compose up -d
    } else {
      docker compose up --build -d
    }
  }

  if (-not $SkipPull) {
    Invoke-Step "Ensuring Ollama model is available: $Model" {
      docker compose exec ollama ollama pull $Model
    }
  }

  Invoke-Step "Seeding local API keys" {
    docker compose exec `
      -e CLIENT_API_KEY=$ClientApiKey `
      -e ADMIN_API_KEY=$AdminApiKey `
      api node dist/scripts/seedKeys.js
  }

  $env:LIVE_API_BASE_URL = $ApiBaseUrl
  $env:LIVE_CLIENT_API_KEY = $ClientApiKey
  $env:ADVERSARIAL_CASES_FILE = $CasesFile
  $env:ADVERSARIAL_REPORT_PATH = $ReportPath

  Invoke-Step "Running adversarial canary cases" {
    & ".\node_modules\.bin\tsx.cmd" scripts/runAdversarialCanaryCases.ts
  }

  Write-Host ""
  Write-Host "Adversarial canary report written to $ReportPath" -ForegroundColor Green
  Write-Host "Raw results written to .test-artifacts/adversarial-canary-results.json" -ForegroundColor Green
} finally {
  if ($null -eq $previousDebugLogs) { Remove-Item Env:\LLM_CANARY_DEBUG_LOGS -ErrorAction SilentlyContinue } else { $env:LLM_CANARY_DEBUG_LOGS = $previousDebugLogs }
  if ($null -eq $previousApiBaseUrl) { Remove-Item Env:\LIVE_API_BASE_URL -ErrorAction SilentlyContinue } else { $env:LIVE_API_BASE_URL = $previousApiBaseUrl }
  if ($null -eq $previousClientKey) { Remove-Item Env:\LIVE_CLIENT_API_KEY -ErrorAction SilentlyContinue } else { $env:LIVE_CLIENT_API_KEY = $previousClientKey }
  if ($null -eq $previousCases) { Remove-Item Env:\ADVERSARIAL_CASES_FILE -ErrorAction SilentlyContinue } else { $env:ADVERSARIAL_CASES_FILE = $previousCases }
  if ($null -eq $previousReport) { Remove-Item Env:\ADVERSARIAL_REPORT_PATH -ErrorAction SilentlyContinue } else { $env:ADVERSARIAL_REPORT_PATH = $previousReport }
  if ($null -eq $previousCanaryModel) { Remove-Item Env:\OPENAI_CANARY_MODEL -ErrorAction SilentlyContinue } else { $env:OPENAI_CANARY_MODEL = $previousCanaryModel }
}
