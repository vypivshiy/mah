$config = Invoke-RestMethod -Uri 'https://max.ru/_api_/config' `
  -Headers @{
    'User-Agent'      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0'
    'Accept'          = '*/*'
    'Accept-Language'  = 'en-US,en;q=0.9'
    'Referer'         = 'https://download.max.ru/'
    'Origin'          = 'https://download.max.ru'
  }

$url = $config.windowsDesktop
if (-not $url) { throw "Key 'windowsDesktop' not found in config" }

Write-Host "Downloading: $url"
Invoke-WebRequest -Uri $url -OutFile 'MAX.msi' -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0'
Write-Host "Saved to MAX.msi"
