# Use: $env:DO_TOKEN = "your-token" before running
$token = $env:DO_TOKEN
if (-not $token) {
    Write-Host "Erro: Defina a variavel de ambiente DO_TOKEN primeiro" -ForegroundColor Red
    Write-Host "Exemplo: `$env:DO_TOKEN = 'seu-token-aqui'" -ForegroundColor Yellow
    exit 1
}

$headers = @{ 
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json" 
}

Write-Host "Listando Droplets..." -ForegroundColor Cyan
$droplets = Invoke-RestMethod -Uri "https://api.digitalocean.com/v2/droplets" -Headers $headers -Method Get

foreach ($d in $droplets.droplets) {
    $ip = ($d.networks.v4 | Where-Object { $_.type -eq "public" }).ip_address
    Write-Host "ID: $($d.id) | Nome: $($d.name) | IP: $ip | Status: $($d.status)" -ForegroundColor Green
}
