# =============================================================================
# NEXUS Cloaker - PowerShell Deploy Script for DigitalOcean
# =============================================================================

param(
    [string]$ApiToken = "",
    [string]$DropletName = "nexus-cloaker",
    [string]$Region = "nyc1",
    [string]$Size = "s-1vcpu-2gb"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "          NEXUS CLOAKER - DEPLOYMENT SCRIPT              " -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host ""

# Check API Token
if ([string]::IsNullOrEmpty($ApiToken)) {
    $ApiToken = Read-Host "Digite seu DigitalOcean API Token"
}

$Headers = @{
    "Authorization" = "Bearer $ApiToken"
    "Content-Type" = "application/json"
}

# Test API connection
try {
    $account = Invoke-RestMethod -Uri "https://api.digitalocean.com/v2/account" -Headers $Headers -Method Get
    Write-Host "[OK] Conectado a DigitalOcean como: $($account.account.email)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Erro ao conectar a DigitalOcean. Verifique seu API Token." -ForegroundColor Red
    exit 1
}

# List existing droplets
Write-Host ""
Write-Host "[INFO] Verificando droplets existentes..." -ForegroundColor Yellow

$droplets = Invoke-RestMethod -Uri "https://api.digitalocean.com/v2/droplets" -Headers $Headers -Method Get

$existingDroplet = $droplets.droplets | Where-Object { $_.name -eq $DropletName }

if ($existingDroplet) {
    $DropletIP = ($existingDroplet.networks.v4 | Where-Object { $_.type -eq "public" }).ip_address
    Write-Host "[INFO] Droplet '$DropletName' ja existe!" -ForegroundColor Yellow
    Write-Host "       IP: $DropletIP" -ForegroundColor Cyan
    
    $choice = Read-Host "Deseja usar este droplet existente? (S/n)"
    if ($choice -eq "n" -or $choice -eq "N") {
        Write-Host "[INFO] Deletando droplet existente..." -ForegroundColor Yellow
        Invoke-RestMethod -Uri "https://api.digitalocean.com/v2/droplets/$($existingDroplet.id)" -Headers $Headers -Method Delete
        Start-Sleep -Seconds 10
        $DropletIP = $null
    }
}

if (-not $DropletIP) {
    # List existing SSH Keys
    Write-Host "[INFO] Verificando SSH Keys existentes..." -ForegroundColor Yellow
    
    $sshKeys = Invoke-RestMethod -Uri "https://api.digitalocean.com/v2/account/keys" -Headers $Headers -Method Get
    
    if ($sshKeys.ssh_keys.Count -gt 0) {
        Write-Host "[INFO] SSH Keys disponiveis:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $sshKeys.ssh_keys.Count; $i++) {
            Write-Host "  $($i + 1)) $($sshKeys.ssh_keys[$i].name) (ID: $($sshKeys.ssh_keys[$i].id))" -ForegroundColor Gray
        }
        $keyChoice = Read-Host "Escolha uma key (1-$($sshKeys.ssh_keys.Count)) ou Enter para criar nova"
        
        if ([string]::IsNullOrEmpty($keyChoice)) {
            # Use first key by default
            $sshKeyId = $sshKeys.ssh_keys[0].id
            Write-Host "[OK] Usando SSH Key padrao: $($sshKeys.ssh_keys[0].name)" -ForegroundColor Green
        } elseif ($keyChoice -match '^\d+$') {
            $keyIndex = [int]$keyChoice - 1
            if ($keyIndex -ge 0 -and $keyIndex -lt $sshKeys.ssh_keys.Count) {
                $sshKeyId = $sshKeys.ssh_keys[$keyIndex].id
                Write-Host "[OK] Usando SSH Key: $($sshKeys.ssh_keys[$keyIndex].name)" -ForegroundColor Green
            }
        }
    }
    
    if (-not $sshKeyId) {
        # Create new SSH key using API
        Write-Host "[INFO] Criando nova SSH Key..." -ForegroundColor Yellow
        
        # Generate a simple RSA key using .NET
        $keyName = "nexus-cloaker-key-$(Get-Date -Format 'yyyyMMddHHmmss')"
        
        # Use PowerShell to generate key if possible, otherwise prompt
        $sshKeyPath = "$env:USERPROFILE\.ssh"
        if (-not (Test-Path $sshKeyPath)) {
            New-Item -ItemType Directory -Path $sshKeyPath -Force | Out-Null
        }
        
        # Try using Windows OpenSSH
        $sshKeygenPath = "C:\Windows\System32\OpenSSH\ssh-keygen.exe"
        if (-not (Test-Path $sshKeygenPath)) {
            $sshKeygenPath = "C:\Program Files\Git\usr\bin\ssh-keygen.exe"
        }
        
        if (Test-Path $sshKeygenPath) {
            $keyFile = "$sshKeyPath\id_rsa_nexus"
            if (Test-Path $keyFile) {
                Remove-Item $keyFile -Force
                Remove-Item "$keyFile.pub" -Force -ErrorAction SilentlyContinue
            }
            & $sshKeygenPath -t rsa -b 4096 -f $keyFile -N '""' -q
            $publicKey = Get-Content "$keyFile.pub"
        } else {
            Write-Host "[AVISO] ssh-keygen nao encontrado." -ForegroundColor Yellow
            Write-Host "Cole sua chave publica SSH (id_rsa.pub):" -ForegroundColor Cyan
            $publicKey = Read-Host
        }
        
        if ($publicKey) {
            $keyBody = @{
                name = $keyName
                public_key = $publicKey
            } | ConvertTo-Json
            
            try {
                $newKey = Invoke-RestMethod -Uri "https://api.digitalocean.com/v2/account/keys" -Headers $Headers -Method Post -Body $keyBody
                $sshKeyId = $newKey.ssh_key.id
                Write-Host "[OK] SSH Key criada: $sshKeyId" -ForegroundColor Green
            } catch {
                Write-Host "[ERRO] Falha ao criar SSH Key: $_" -ForegroundColor Red
            }
        }
    }
    
    if (-not $sshKeyId) {
        Write-Host "[ERRO] Nenhuma SSH Key configurada. Continuando sem SSH Key..." -ForegroundColor Yellow
    }
    
    # Create Droplet with user-data for auto setup
    Write-Host ""
    Write-Host "[INFO] Criando Droplet '$DropletName'..." -ForegroundColor Yellow
    Write-Host "       Regiao: $Region" -ForegroundColor Gray
    Write-Host "       Tamanho: $Size (1 vCPU, 2GB RAM)" -ForegroundColor Gray
    
    # Cloud-init script
    $userData = @"
#!/bin/bash
set -e

# Update system
apt-get update
apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
rm get-docker.sh

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-Linux-x86_64" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Create app directory
mkdir -p /opt/cloaker/data

# Signal ready
touch /opt/cloaker/.ready
"@
    
    $dropletBody = @{
        name = $DropletName
        region = $Region
        size = $Size
        image = "ubuntu-22-04-x64"
        ssh_keys = @($sshKeyId)
        backups = $false
        ipv6 = $false
        monitoring = $true
        tags = @("cloaker")
        user_data = $userData
    } | ConvertTo-Json
    
    try {
        $newDroplet = Invoke-RestMethod -Uri "https://api.digitalocean.com/v2/droplets" -Headers $Headers -Method Post -Body $dropletBody
        $DropletId = $newDroplet.droplet.id
        
        Write-Host "[OK] Droplet criado! ID: $DropletId" -ForegroundColor Green
        Write-Host "[INFO] Aguardando inicializacao (pode demorar 2-3 minutos)..." -ForegroundColor Yellow
        
        # Wait for droplet to be ready
        $attempts = 0
        $maxAttempts = 30
        do {
            Start-Sleep -Seconds 10
            $droplet = Invoke-RestMethod -Uri "https://api.digitalocean.com/v2/droplets/$DropletId" -Headers $Headers -Method Get
            $status = $droplet.droplet.status
            $attempts++
            Write-Host "       Status: $status (tentativa $attempts/$maxAttempts)" -ForegroundColor Gray
        } while ($status -ne "active" -and $attempts -lt $maxAttempts)
        
        if ($status -ne "active") {
            Write-Host "[ERRO] Droplet nao ficou ativo a tempo." -ForegroundColor Red
            exit 1
        }
        
        $DropletIP = ($droplet.droplet.networks.v4 | Where-Object { $_.type -eq "public" }).ip_address
        
        Write-Host ""
        Write-Host "[OK] Droplet pronto!" -ForegroundColor Green
        Write-Host "    IP: $DropletIP" -ForegroundColor Cyan
        
        # Wait more for cloud-init
        Write-Host "[INFO] Aguardando setup inicial (Docker)..." -ForegroundColor Yellow
        Start-Sleep -Seconds 60
        
    } catch {
        Write-Host "[ERRO] Falha ao criar Droplet: $_" -ForegroundColor Red
        exit 1
    }
}

# Output deployment instructions
Write-Host ""
Write-Host "=========================================================" -ForegroundColor Green
Write-Host "          DROPLET CRIADO COM SUCESSO!                    " -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  IP do Servidor: $DropletIP" -ForegroundColor Cyan
Write-Host ""
Write-Host "  PROXIMOS PASSOS:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1. Acesse o servidor via SSH:" -ForegroundColor White
Write-Host "     ssh root@$DropletIP" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. Clone/copie os arquivos do cloaker:" -ForegroundColor White
Write-Host "     mkdir -p /opt/cloaker && cd /opt/cloaker" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. Inicie o cloaker:" -ForegroundColor White
Write-Host "     docker-compose up -d --build" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. Acesse o dashboard:" -ForegroundColor White
Write-Host "     http://${DropletIP}:8081" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Credenciais padrao:" -ForegroundColor Yellow
Write-Host "    Usuario: admin" -ForegroundColor White
Write-Host "    Senha:   admin123" -ForegroundColor White
Write-Host ""
Write-Host "  [!] IMPORTANTE: Altere a senha padrao apos o primeiro login!" -ForegroundColor Red
Write-Host ""

# Save info to file
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CloakerDir = Split-Path -Parent $ScriptDir
$infoFile = "$CloakerDir\deployment-info.txt"

@"
NEXUS Cloaker - Deployment Info
===============================
Date: $(Get-Date)
Droplet IP: $DropletIP

Dashboard: http://${DropletIP}:8081
Proxy: http://${DropletIP}

Default credentials:
  Username: admin
  Password: admin123 (CHANGE THIS!)

SSH Access:
  ssh root@$DropletIP

Deploy commands:
  scp -r ./* root@${DropletIP}:/opt/cloaker/
  ssh root@$DropletIP "cd /opt/cloaker && docker-compose up -d --build"
"@ | Out-File $infoFile -Encoding UTF8

Write-Host "  Info salvo em: $infoFile" -ForegroundColor Gray
Write-Host ""
