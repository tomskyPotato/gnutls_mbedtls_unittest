$WorkDir = (Get-Location).Path
$OpenSSLPath = "$WorkDir\OpenSSL-Win64\bin\openssl.exe"
try { & $OpenSSLPath version | Out-Null } catch { Write-Error "OpenSSL fehlt"; exit 1 }
Write-Host "Verbinde zu localhost:5556..."
& $OpenSSLPath s_client -connect localhost:5556 -CAfile "$WorkDir\server-cert.pem"