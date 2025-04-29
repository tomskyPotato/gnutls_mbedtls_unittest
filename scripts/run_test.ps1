$WorkDir = (Get-Location).Path
cd $WorkDir
Start-Process powershell -ArgumentList "-NoExit", "-File", "open_local_ssl_server.ps1"
Start-Sleep -Seconds 2
Start-Process powershell -ArgumentList "-NoExit", "-File", "test_tls_client.ps1"
#.\build\test_mbedtls.exe