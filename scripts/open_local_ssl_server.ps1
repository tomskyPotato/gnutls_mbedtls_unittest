# PowerShell-Skript zum Testen der OpenSSL-Verfügbarkeit

# Konfiguration
$ServerPort = 5556 # Port, auf dem der Server lauscht
$ServerAddress = "localhost" # Adresse des Servers

$WorkDir = (Get-Location).Path
$OpenSSLPath = "$WorkDir\OpenSSL-Win64\bin\openssl.exe"
$CertFile = "$WorkDir\server-cert.pem"
$KeyFile = "$WorkDir\server-key.pem"

try { & $OpenSSLPath version | Out-Null } catch { Write-Error "OpenSSL fehlt"; exit 1 }
if (-not (Test-Path $CertFile) -or -not (Test-Path $KeyFile)) { Write-Error "Zertifikate fehlen"; exit 1 }
Write-Host "Starte TLS-Server auf localhost:5556..."
& $OpenSSLPath s_server -accept $ServerPort -cert $CertFile -key $KeyFile