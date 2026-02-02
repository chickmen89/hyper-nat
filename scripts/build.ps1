# Hyper-NAT Build Script for Windows
# Run from project root: .\scripts\build.ps1

param(
    [switch]$Release,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$OutputDir = Join-Path $ProjectRoot "build"
$BinaryName = "hyper-nat.exe"

# Version info
$Version = "0.1.0"
$BuildTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "Hyper-NAT Build Script" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan

# Clean build
if ($Clean) {
    Write-Host "Cleaning build directory..." -ForegroundColor Yellow
    if (Test-Path $OutputDir) {
        Remove-Item -Recurse -Force $OutputDir
    }
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Set working directory
Push-Location $ProjectRoot

try {
    # Download dependencies
    Write-Host "Downloading dependencies..." -ForegroundColor Yellow
    go mod tidy
    if ($LASTEXITCODE -ne 0) {
        throw "go mod tidy failed"
    }

    # Run tests
    Write-Host "Running tests..." -ForegroundColor Yellow
    go test ./config/... ./nat/...
    if ($LASTEXITCODE -ne 0) {
        throw "Tests failed"
    }

    # Build
    Write-Host "Building..." -ForegroundColor Yellow

    $LdFlags = "-X 'main.version=$Version' -X 'main.buildTime=$BuildTime'"
    if ($Release) {
        $LdFlags += " -s -w"  # Strip debug info for release
    }

    $env:CGO_ENABLED = "0"
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"

    go build -ldflags $LdFlags -o (Join-Path $OutputDir $BinaryName) ./cmd/hyper-nat
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }

    # Copy config file
    Copy-Item (Join-Path $ProjectRoot "configs\hyper-nat.yaml") $OutputDir

    Write-Host ""
    Write-Host "Build successful!" -ForegroundColor Green
    Write-Host "Output: $OutputDir\$BinaryName" -ForegroundColor Green
    Write-Host ""
    Write-Host "Note: You need to download WinDivert files and place them in the build directory:" -ForegroundColor Yellow
    Write-Host "  - WinDivert.dll" -ForegroundColor Yellow
    Write-Host "  - WinDivert64.sys" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Download from: https://reqrypt.org/windivert.html" -ForegroundColor Cyan

} finally {
    Pop-Location
}
