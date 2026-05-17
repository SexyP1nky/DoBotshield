param([string]$NucleiDir)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $NucleiDir) {
    $NucleiDir = Join-Path $PSScriptRoot "nuclei"
}

if (-not (Test-Path $NucleiDir)) {
    New-Item -ItemType Directory -Path $NucleiDir -Force | Out-Null
}

try {
    Write-Host "       Buscando ultima release..."
    $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/projectdiscovery/nuclei/releases/latest' -UseBasicParsing
    Write-Host "       Versao: $($rel.tag_name)"

    $asset = $rel.assets | Where-Object { $_.name -match 'windows.*amd64.*\.zip$' } | Select-Object -First 1
    if (-not $asset) {
        throw "Asset windows_amd64.zip nao encontrado na release $($rel.tag_name)"
    }

    Write-Host "       Baixando: $($asset.name)..."
    $zipPath = Join-Path $NucleiDir "nuclei.zip"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing

    Write-Host "       Extraindo..."
    Expand-Archive -Path $zipPath -DestinationPath $NucleiDir -Force
    Remove-Item $zipPath -Force

    $exe = Join-Path $NucleiDir "nuclei.exe"
    if (Test-Path $exe) {
        Write-Host "       OK: nuclei.exe instalado."
        exit 0
    } else {
        throw "nuclei.exe nao encontrado apos extracao"
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
