param(
  [string]$ApiBaseUrl = "http://localhost:3000",
  [string]$ClientApiKey = "comparison-local-dev-key",
  [int]$ClientRateLimitPerMinute = 10000,
  [string]$Model = "qwen3:4b-instruct",
  [string]$ProviderBaseUrl = "http://127.0.0.1:11434/v1",
  [string]$CasesFile = "test/fixtures/adversarial-cases.json",
  [string]$ReportPath = "gateway-comparison-report.html",
  [int]$Runs = 3,
  [int]$Concurrency = 1,
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
    if ($Name -like "*Ollama*") {
      throw "Step failed with exit code $LASTEXITCODE`: $Name. Docker Ollama GPU mode requires the NVIDIA Container Toolkit on the host and an available GPU runtime."
    }
    throw "Step failed with exit code $LASTEXITCODE`: $Name"
  }
}

$previousDetectionMode = [Environment]::GetEnvironmentVariable("INJECTION_DETECTION_MODE", "Process")
$previousDebugLogs = [Environment]::GetEnvironmentVariable("LLM_CANARY_DEBUG_LOGS", "Process")
$previousCanaryModel = [Environment]::GetEnvironmentVariable("OPENAI_CANARY_MODEL", "Process")
$previousModelAliases = [Environment]::GetEnvironmentVariable("OPENAI_MODEL_ALIASES", "Process")
$previousOpenAiBaseUrl = [Environment]::GetEnvironmentVariable("OPENAI_BASE_URL", "Process")
$previousOpenAiKey = [Environment]::GetEnvironmentVariable("OPENAI_API_KEY", "Process")
$previousApiBaseUrl = [Environment]::GetEnvironmentVariable("LIVE_API_BASE_URL", "Process")
$previousClientKey = [Environment]::GetEnvironmentVariable("LIVE_CLIENT_API_KEY", "Process")
$previousProviderBaseUrl = [Environment]::GetEnvironmentVariable("COMPARISON_PROVIDER_BASE_URL", "Process")
$previousCases = [Environment]::GetEnvironmentVariable("COMPARISON_CASES_FILE", "Process")
$previousReport = [Environment]::GetEnvironmentVariable("COMPARISON_REPORT_PATH", "Process")
$previousJson = [Environment]::GetEnvironmentVariable("COMPARISON_JSON_PATH", "Process")
$previousRuns = [Environment]::GetEnvironmentVariable("COMPARISON_RUNS", "Process")
$previousConcurrency = [Environment]::GetEnvironmentVariable("COMPARISON_CONCURRENCY", "Process")
$previousOpenAiModel = [Environment]::GetEnvironmentVariable("OPENAI_MODEL", "Process")
$composeEnvPath = ".test-artifacts\gateway-comparison-compose.env"
$composeOverridePath = ".test-artifacts\gateway-comparison-compose.override.yml"

try {
  New-Item -ItemType Directory -Force -Path ".test-artifacts" | Out-Null
  $composeEnvLines = @(
    "INJECTION_DETECTION_MODE=llm_canary",
    "LLM_CANARY_DEBUG_LOGS=true",
    "OPENAI_API_KEY=ollama",
    "OPENAI_BASE_URL=http://ollama:11434/v1",
    "OPENAI_CANARY_MODEL=$Model"
  )
  [System.IO.File]::WriteAllLines(
    (Join-Path (Get-Location) $composeEnvPath),
    $composeEnvLines,
    [System.Text.UTF8Encoding]::new($false)
  )
  $composeOverrideLines = @(
    "services:",
    "  api:",
    "    environment:",
    "      OPENAI_API_KEY: ollama",
    "      OPENAI_BASE_URL: http://ollama:11434/v1",
    "      OPENAI_CANARY_MODEL: $Model",
    "      OPENAI_MODEL_ALIASES: '{`"gpt-4o`":`"$Model`",`"claude-3-5-sonnet`":`"$Model`"}'"
  )
  [System.IO.File]::WriteAllLines(
    (Join-Path (Get-Location) $composeOverridePath),
    $composeOverrideLines,
    [System.Text.UTF8Encoding]::new($false)
  )

  $env:OPENAI_API_KEY = "ollama"
  $env:OPENAI_BASE_URL = $ProviderBaseUrl
  $env:OPENAI_CANARY_MODEL = $Model
  $env:OPENAI_MODEL = "gpt-4o"
  $env:OPENAI_MODEL_ALIASES = "{`"gpt-4o`":`"$Model`",`"claude-3-5-sonnet`":`"$Model`"}"

  Invoke-Step "Starting Docker Compose stack for gateway comparison" {
    if ($NoBuild) {
      docker compose --env-file $composeEnvPath -f docker-compose.yml -f $composeOverridePath up -d
    } else {
      docker compose --env-file $composeEnvPath -f docker-compose.yml -f $composeOverridePath up --build -d
    }
  }

  if (-not $SkipPull) {
    Invoke-Step "Ensuring Docker Ollama model is available: $Model" {
      docker compose --env-file $composeEnvPath -f docker-compose.yml -f $composeOverridePath exec ollama ollama pull $Model
    }
  } else {
    Invoke-Step "Checking Docker Ollama is reachable" {
      docker compose --env-file $composeEnvPath -f docker-compose.yml -f $composeOverridePath exec ollama ollama --version
    }
  }

  Invoke-Step "Seeding local API key" {
    docker compose --env-file $composeEnvPath -f docker-compose.yml -f $composeOverridePath exec `
      -e CLIENT_API_KEY=$ClientApiKey `
      -e CLIENT_RATE_LIMIT_PER_MINUTE=$ClientRateLimitPerMinute `
      api node dist/scripts/seedKeys.js
  }

  $env:LIVE_API_BASE_URL = $ApiBaseUrl
  $env:LIVE_CLIENT_API_KEY = $ClientApiKey
  $env:COMPARISON_PROVIDER_BASE_URL = $ProviderBaseUrl
  $env:COMPARISON_CASES_FILE = $CasesFile
  $env:COMPARISON_REPORT_PATH = $ReportPath
  $env:COMPARISON_JSON_PATH = ".test-artifacts/gateway-comparison-results.json"
  $env:COMPARISON_RUNS = [string]$Runs
  $env:COMPARISON_CONCURRENCY = [string]$Concurrency

  Invoke-Step "Running gateway comparison cases" {
    & ".\node_modules\.bin\tsx.cmd" scripts/runGatewayComparison.ts
  }

  Write-Host ""
  Write-Host "Gateway comparison report written to $ReportPath" -ForegroundColor Green
  Write-Host "Raw results written to .test-artifacts/gateway-comparison-results.json" -ForegroundColor Green
} finally {
  if ($null -eq $previousDetectionMode) { Remove-Item Env:\INJECTION_DETECTION_MODE -ErrorAction SilentlyContinue } else { $env:INJECTION_DETECTION_MODE = $previousDetectionMode }
  if ($null -eq $previousDebugLogs) { Remove-Item Env:\LLM_CANARY_DEBUG_LOGS -ErrorAction SilentlyContinue } else { $env:LLM_CANARY_DEBUG_LOGS = $previousDebugLogs }
  if ($null -eq $previousCanaryModel) { Remove-Item Env:\OPENAI_CANARY_MODEL -ErrorAction SilentlyContinue } else { $env:OPENAI_CANARY_MODEL = $previousCanaryModel }
  if ($null -eq $previousModelAliases) { Remove-Item Env:\OPENAI_MODEL_ALIASES -ErrorAction SilentlyContinue } else { $env:OPENAI_MODEL_ALIASES = $previousModelAliases }
  if ($null -eq $previousOpenAiBaseUrl) { Remove-Item Env:\OPENAI_BASE_URL -ErrorAction SilentlyContinue } else { $env:OPENAI_BASE_URL = $previousOpenAiBaseUrl }
  if ($null -eq $previousOpenAiKey) { Remove-Item Env:\OPENAI_API_KEY -ErrorAction SilentlyContinue } else { $env:OPENAI_API_KEY = $previousOpenAiKey }
  if ($null -eq $previousApiBaseUrl) { Remove-Item Env:\LIVE_API_BASE_URL -ErrorAction SilentlyContinue } else { $env:LIVE_API_BASE_URL = $previousApiBaseUrl }
  if ($null -eq $previousClientKey) { Remove-Item Env:\LIVE_CLIENT_API_KEY -ErrorAction SilentlyContinue } else { $env:LIVE_CLIENT_API_KEY = $previousClientKey }
  if ($null -eq $previousProviderBaseUrl) { Remove-Item Env:\COMPARISON_PROVIDER_BASE_URL -ErrorAction SilentlyContinue } else { $env:COMPARISON_PROVIDER_BASE_URL = $previousProviderBaseUrl }
  if ($null -eq $previousCases) { Remove-Item Env:\COMPARISON_CASES_FILE -ErrorAction SilentlyContinue } else { $env:COMPARISON_CASES_FILE = $previousCases }
  if ($null -eq $previousReport) { Remove-Item Env:\COMPARISON_REPORT_PATH -ErrorAction SilentlyContinue } else { $env:COMPARISON_REPORT_PATH = $previousReport }
  if ($null -eq $previousJson) { Remove-Item Env:\COMPARISON_JSON_PATH -ErrorAction SilentlyContinue } else { $env:COMPARISON_JSON_PATH = $previousJson }
  if ($null -eq $previousRuns) { Remove-Item Env:\COMPARISON_RUNS -ErrorAction SilentlyContinue } else { $env:COMPARISON_RUNS = $previousRuns }
  if ($null -eq $previousConcurrency) { Remove-Item Env:\COMPARISON_CONCURRENCY -ErrorAction SilentlyContinue } else { $env:COMPARISON_CONCURRENCY = $previousConcurrency }
  if ($null -eq $previousOpenAiModel) { Remove-Item Env:\OPENAI_MODEL -ErrorAction SilentlyContinue } else { $env:OPENAI_MODEL = $previousOpenAiModel }
  Remove-Item $composeEnvPath -ErrorAction SilentlyContinue
  Remove-Item $composeOverridePath -ErrorAction SilentlyContinue
}
