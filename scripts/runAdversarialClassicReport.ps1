param(
  [string]$ApiBaseUrl = "http://localhost:3000",
  [string]$ClientApiKey = "client-local-dev-key",
  [string]$AdminApiKey = "admin-local-dev-key",
  [string]$Model = "gpt-oss:20b",
  [string]$CasesFile = "test/fixtures/adversarial-cases.json",
  [string]$ReportPath = "adversarial-classic-report.html",
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
$previousDetectionMode = [Environment]::GetEnvironmentVariable("INJECTION_DETECTION_MODE", "Process")
$previousApiBaseUrl = [Environment]::GetEnvironmentVariable("LIVE_API_BASE_URL", "Process")
$previousClientKey = [Environment]::GetEnvironmentVariable("LIVE_CLIENT_API_KEY", "Process")
$previousAdminKey = [Environment]::GetEnvironmentVariable("LIVE_ADMIN_API_KEY", "Process")
$previousCases = [Environment]::GetEnvironmentVariable("ADVERSARIAL_CASES_FILE", "Process")
$previousReport = [Environment]::GetEnvironmentVariable("ADVERSARIAL_REPORT_PATH", "Process")
$previousJson = [Environment]::GetEnvironmentVariable("ADVERSARIAL_JSON_PATH", "Process")
$previousAdversarialMode = [Environment]::GetEnvironmentVariable("ADVERSARIAL_MODE", "Process")

try {
  $env:INJECTION_DETECTION_MODE = "classic"
  $env:LLM_CANARY_DEBUG_LOGS = "false"

  Invoke-Step "Starting Docker Compose stack in classic detection mode" {
    if ($NoBuild) {
      docker compose up -d
    } else {
      docker compose up --build -d
    }
  }

  if (-not $SkipPull) {
    Invoke-Step "Ensuring Ollama chat model is available: $Model" {
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
  $env:LIVE_ADMIN_API_KEY = $AdminApiKey
  $env:ADVERSARIAL_CASES_FILE = $CasesFile
  $env:ADVERSARIAL_REPORT_PATH = $ReportPath
  $env:ADVERSARIAL_JSON_PATH = ".test-artifacts/adversarial-classic-results.json"
  $env:ADVERSARIAL_MODE = "classic"

  Invoke-Step "Running adversarial classic cases" {
    & ".\node_modules\.bin\tsx.cmd" scripts/runAdversarialCases.ts
  }

  Write-Host ""
  Write-Host "Adversarial classic report written to $ReportPath" -ForegroundColor Green
  Write-Host "Raw results written to .test-artifacts/adversarial-classic-results.json" -ForegroundColor Green
} finally {
  if ($null -eq $previousDebugLogs) { Remove-Item Env:\LLM_CANARY_DEBUG_LOGS -ErrorAction SilentlyContinue } else { $env:LLM_CANARY_DEBUG_LOGS = $previousDebugLogs }
  if ($null -eq $previousDetectionMode) { Remove-Item Env:\INJECTION_DETECTION_MODE -ErrorAction SilentlyContinue } else { $env:INJECTION_DETECTION_MODE = $previousDetectionMode }
  if ($null -eq $previousApiBaseUrl) { Remove-Item Env:\LIVE_API_BASE_URL -ErrorAction SilentlyContinue } else { $env:LIVE_API_BASE_URL = $previousApiBaseUrl }
  if ($null -eq $previousClientKey) { Remove-Item Env:\LIVE_CLIENT_API_KEY -ErrorAction SilentlyContinue } else { $env:LIVE_CLIENT_API_KEY = $previousClientKey }
  if ($null -eq $previousAdminKey) { Remove-Item Env:\LIVE_ADMIN_API_KEY -ErrorAction SilentlyContinue } else { $env:LIVE_ADMIN_API_KEY = $previousAdminKey }
  if ($null -eq $previousCases) { Remove-Item Env:\ADVERSARIAL_CASES_FILE -ErrorAction SilentlyContinue } else { $env:ADVERSARIAL_CASES_FILE = $previousCases }
  if ($null -eq $previousReport) { Remove-Item Env:\ADVERSARIAL_REPORT_PATH -ErrorAction SilentlyContinue } else { $env:ADVERSARIAL_REPORT_PATH = $previousReport }
  if ($null -eq $previousJson) { Remove-Item Env:\ADVERSARIAL_JSON_PATH -ErrorAction SilentlyContinue } else { $env:ADVERSARIAL_JSON_PATH = $previousJson }
  if ($null -eq $previousAdversarialMode) { Remove-Item Env:\ADVERSARIAL_MODE -ErrorAction SilentlyContinue } else { $env:ADVERSARIAL_MODE = $previousAdversarialMode }
}
