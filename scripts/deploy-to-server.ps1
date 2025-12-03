$ServerIP = "198.199.79.100"

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "   NEXUS CLOAKER - DEPLOY PARA $ServerIP" -ForegroundColor Cyan  
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host ""

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CloakerDir = Split-Path -Parent $ScriptDir

Write-Host "[INFO] Preparando arquivos para deploy..." -ForegroundColor Yellow

# Create tar archive
$tempDir = "$env:TEMP\cloaker_deploy"
$tempTar = "$tempDir\cloaker.tar"

if (Test-Path $tempDir) {
    Remove-Item $tempDir -Recurse -Force
}
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Copy files to temp (excluding scripts and git)
Write-Host "[INFO] Copiando arquivos..." -ForegroundColor Gray
$excludes = @(".git", "*.ps1", "deployment-info.txt", ".gitkeep")
Get-ChildItem $CloakerDir -Exclude $excludes | Copy-Item -Destination $tempDir -Recurse -Force

# Create tar using Windows tar
Push-Location $tempDir
tar -cvf cloaker.tar *
Pop-Location

Write-Host "[OK] Arquivo criado: $tempTar" -ForegroundColor Green
Write-Host ""
Write-Host "[INFO] Enviando para servidor $ServerIP..." -ForegroundColor Yellow
Write-Host "[!] Voce pode precisar digitar a senha SSH" -ForegroundColor Yellow
Write-Host ""

# Use Windows OpenSSH
$sshPath = "C:\Windows\System32\OpenSSH\ssh.exe"
$scpPath = "C:\Windows\System32\OpenSSH\scp.exe"

# SCP the tar file
& $scpPath -o StrictHostKeyChecking=no "$tempTar" "root@${ServerIP}:/tmp/cloaker.tar"

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERRO] Falha ao enviar arquivos. Verifique a conexao SSH." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[OK] Arquivos enviados!" -ForegroundColor Green
Write-Host "[INFO] Configurando servidor..." -ForegroundColor Yellow
Write-Host ""

# SSH and setup
& $sshPath -o StrictHostKeyChecking=no "root@$ServerIP" @'
set -e
echo "[1/6] Limpando instalacao anterior..."
rm -rf /opt/cloaker 2>/dev/null || true
docker stop $(docker ps -q) 2>/dev/null || true
docker rm $(docker ps -aq) 2>/dev/null || true

echo "[2/6] Instalando Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
fi

echo "[3/6] Instalando Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-Linux-x86_64" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

echo "[4/6] Extraindo arquivos..."
mkdir -p /opt/cloaker
cd /opt/cloaker
tar -xvf /tmp/cloaker.tar
rm /tmp/cloaker.tar

echo "[5/6] Gerando configuracoes seguras..."
JWT_SECRET=$(openssl rand -hex 32)
ADMIN_PASS=$(openssl rand -base64 12)
sed -i "s/CHANGE-THIS-TO-A-SECURE-RANDOM-STRING/$JWT_SECRET/" config.yaml
sed -i "s/admin123/$ADMIN_PASS/" config.yaml

echo "[6/6] Iniciando containers..."
docker-compose up -d --build

sleep 10
docker-compose ps

echo ""
echo "========================================================="
echo "            INSTALACAO CONCLUIDA!"
echo "========================================================="
echo ""
echo "Dashboard: http://$(curl -s ifconfig.me):8081"
echo "Proxy: http://$(curl -s ifconfig.me)"
echo ""
echo "Credenciais:"
echo "  Usuario: admin"
echo "  Senha: $ADMIN_PASS"
echo ""
echo "SALVE ESTA SENHA! Ela foi gerada automaticamente."
echo ""
'@

# Cleanup
Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Green
Write-Host "              DEPLOY CONCLUIDO!" -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard: http://${ServerIP}:8081" -ForegroundColor Cyan
Write-Host "  Proxy:     http://${ServerIP}" -ForegroundColor Cyan
Write-Host ""
Write-Host "  A senha foi exibida no terminal acima - ANOTE ELA!" -ForegroundColor Yellow
Write-Host ""

