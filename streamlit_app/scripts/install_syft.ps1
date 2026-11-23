# Installs Syft (Anchore) for the current user on Windows, without administrator rights.
# Official docs: https://oss.anchore.com/docs/installation/syft/
# Requires Git Bash/WSL-free PowerShell 5.1+. The installer script is downloaded from the official anchore/syft repository.
$ErrorActionPreference = "Stop"
$bin = Join-Path $env:USERPROFILE "bin"
New-Item -ItemType Directory -Force -Path $bin | Out-Null
$bash = (Get-Command bash -ErrorAction SilentlyContinue)
if ($bash) {
    bash -c "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b '$($bin -replace '\\','/')'"
} else {
    # Fallback: download the release zip for windows_amd64 from https://github.com/anchore/syft/releases and extract syft.exe into $bin
    Write-Host "bash not found. Download syft_<version>_windows_amd64.zip from https://github.com/anchore/syft/releases and extract syft.exe to $bin"
    exit 1
}
Write-Host "Installed to $bin. Add it to PATH (or set SYFT_BIN in .env):"
Write-Host "  [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$bin', 'User')"
& (Join-Path $bin "syft.exe") version
