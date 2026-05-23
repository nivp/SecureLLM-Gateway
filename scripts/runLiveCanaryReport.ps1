param(
  [string]$ApiBaseUrl = "http://localhost:3000",
  [string]$ClientApiKey = "client-local-dev-key",
  [string]$AdminApiKey = "admin-local-dev-key",
  [string]$Model = "gpt-oss:20b",
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

$previousRunLive = [Environment]::GetEnvironmentVariable("RUN_LIVE_LLM_TESTS", "Process")
$previousApiBaseUrl = [Environment]::GetEnvironmentVariable("LIVE_API_BASE_URL", "Process")
$previousClientKey = [Environment]::GetEnvironmentVariable("LIVE_CLIENT_API_KEY", "Process")
$previousDebugLogs = [Environment]::GetEnvironmentVariable("LLM_CANARY_DEBUG_LOGS", "Process")
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

  $env:RUN_LIVE_LLM_TESTS = "true"
  $env:LIVE_API_BASE_URL = $ApiBaseUrl
  $env:LIVE_CLIENT_API_KEY = $ClientApiKey

  Invoke-Step "Running live canary integration report" {
    & ".\node_modules\.bin\vitest.cmd" run test/liveCanary.integration.test.ts --reporter json --outputFile test-results.json
    $testExitCode = $LASTEXITCODE

    & ".\node_modules\.bin\tsx.cmd" scripts/renderTestReport.ts
    $renderExitCode = $LASTEXITCODE

    if ($renderExitCode -ne 0) {
      $global:LASTEXITCODE = $renderExitCode
      return
    }
    $global:LASTEXITCODE = $testExitCode
  }

  Write-Host ""
  Write-Host "Live canary report written to test-results.html" -ForegroundColor Green
  Write-Host "Live canary traces written to .test-artifacts/live-canary-traces.json" -ForegroundColor Green
} finally {
  if ($null -eq $previousRunLive) { Remove-Item Env:\RUN_LIVE_LLM_TESTS -ErrorAction SilentlyContinue } else { $env:RUN_LIVE_LLM_TESTS = $previousRunLive }
  if ($null -eq $previousApiBaseUrl) { Remove-Item Env:\LIVE_API_BASE_URL -ErrorAction SilentlyContinue } else { $env:LIVE_API_BASE_URL = $previousApiBaseUrl }
  if ($null -eq $previousClientKey) { Remove-Item Env:\LIVE_CLIENT_API_KEY -ErrorAction SilentlyContinue } else { $env:LIVE_CLIENT_API_KEY = $previousClientKey }
  if ($null -eq $previousDebugLogs) { Remove-Item Env:\LLM_CANARY_DEBUG_LOGS -ErrorAction SilentlyContinue } else { $env:LLM_CANARY_DEBUG_LOGS = $previousDebugLogs }
  if ($null -eq $previousCanaryModel) { Remove-Item Env:\OPENAI_CANARY_MODEL -ErrorAction SilentlyContinue } else { $env:OPENAI_CANARY_MODEL = $previousCanaryModel }
}
