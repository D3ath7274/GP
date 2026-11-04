# Start the checked-out Mintlify documentation independently of the sensor or this terminal.
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)][int]$Port = 3333,
    [ValidateRange(5, 300)][int]$TimeoutSeconds = 120,
    [switch]$Foreground
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$docsRoot = Join-Path $repoRoot 'docs-site'
$url = "http://localhost:$Port/"
$configPath = Join-Path $docsRoot 'docs.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw "Missing docs.json in $docsRoot"
}
$siteName = (Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json).name
if ([string]::IsNullOrWhiteSpace($siteName)) { throw 'docs.json must declare a site name' }
$encodedSiteName = [System.Net.WebUtility]::HtmlEncode($siteName)

function Test-DocsResponse {
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3
        return $response.StatusCode -eq 200 -and
            ($response.Content.Contains($siteName) -or $response.Content.Contains($encodedSiteName))
    } catch {
        return $false
    }
}

if (Test-DocsResponse) {
    Write-Output "Documentation is ready: $url"
    exit 0
}

$node = Get-Command node.exe -ErrorAction Stop
$mint = Get-Command mint.cmd -ErrorAction SilentlyContinue
if (-not $mint) {
    throw 'Install the tested CLI first: npm install --global mint@4.2.1195'
}
$mintEntry = Join-Path (Split-Path -Parent $mint.Source) 'node_modules/mint/index.js'
if (-not (Test-Path -LiteralPath $mintEntry -PathType Leaf)) {
    throw "Cannot locate the Mintlify entry point beside $($mint.Source). Reinstall mint with npm."
}
if ($Foreground) {
    Push-Location -LiteralPath $docsRoot
    try {
        & $node.Source $mintEntry dev --port $Port --no-open
        if ($LASTEXITCODE -ne 0) { throw "Mintlify exited with code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
    exit 0
}

$runtime = Join-Path $repoRoot '.local/docs-preview'
New-Item -ItemType Directory -Path $runtime -Force | Out-Null
$lock = $null
try {
    $lock = [System.IO.File]::Open((Join-Path $runtime 'start.lock'),
        [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None)
    # A second start may have completed while this process was resolving tools.
    if (Test-DocsResponse) {
        Write-Output "Documentation is ready: $url"
        exit 0
    }
    $listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    if ($listener) {
        throw "Port $Port is occupied but is not serving this documentation site. Inspect it before restarting."
    }
    $stdout = Join-Path $runtime "mint-$Port.stdout.log"
    $stderr = Join-Path $runtime "mint-$Port.stderr.log"
    $arguments = @('"' + $mintEntry + '"', 'dev', '--port', "$Port", '--no-open')
    $process = Start-Process -FilePath $node.Source -ArgumentList $arguments -WorkingDirectory $docsRoot `
        -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    @{ pid = $process.Id; port = $Port; url = $url; started_at = [DateTime]::UtcNow.ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtime "mint-$Port.json") -Encoding UTF8
    Write-Output "Starting documentation. Logs: $runtime"
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-DocsResponse) {
            Write-Output "Documentation is ready: $url"
            exit 0
        }
        $process.Refresh()
        if ($process.HasExited) {
            throw "Mintlify exited with code $($process.ExitCode). Read $stderr and $stdout."
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Documentation has not answered within $TimeoutSeconds seconds. Read $stdout and $stderr; the process may still be preparing."
} finally {
    if ($lock) { $lock.Dispose() }
}
