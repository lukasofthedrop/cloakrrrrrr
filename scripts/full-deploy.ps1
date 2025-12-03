# =============================================================================
# NEXUS Cloaker - Full Deploy Script (Windows PowerShell)
# Faz upload e executa setup automaticamente na VPS
# =============================================================================

param(
    [string]$ServerIP = "198.199.79.100",
    [string]$Password = "",  # Set via: $env:SSH_PASSWORD = "your-password"
    [string]$User = "root"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "   NEXUS CLOAKER - DEPLOY COMPLETO" -ForegroundColor Cyan
Write-Host "   Servidor: $ServerIP" -ForegroundColor Gray
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host ""

# Caminhos
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CloakerDir = Split-Path -Parent $ScriptDir
$SshPath = "C:\Windows\System32\OpenSSH\ssh.exe"
$ScpPath = "C:\Windows\System32\OpenSSH\scp.exe"

# Verificar se OpenSSH existe
if (-not (Test-Path $SshPath)) {
    Write-Host "[ERRO] OpenSSH não encontrado em $SshPath" -ForegroundColor Red
    Write-Host "Tente: Add-WindowsCapability -Online -Name OpenSSH.Client*" -ForegroundColor Yellow
    exit 1
}

Write-Host "[1/5] Preparando arquivos para upload..." -ForegroundColor Yellow

# Criar diretório temporário
$TempDir = "$env:TEMP\cloaker_deploy_$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

# Copiar arquivos necessários (excluindo scripts PS1 e arquivos desnecessários)
$FilesToCopy = @(
    "cmd",
    "internal", 
    "data",
    "web",
    "Dockerfile",
    "docker-compose.yml",
    "config.yaml",
    "go.mod",
    "go.sum",
    "Caddyfile",
    "README.md"
)

foreach ($item in $FilesToCopy) {
    $source = Join-Path $CloakerDir $item
    if (Test-Path $source) {
        Copy-Item -Path $source -Destination $TempDir -Recurse -Force
    }
}

# Copiar script de setup remoto
Copy-Item -Path "$ScriptDir\remote-setup.sh" -Destination $TempDir -Force

# Criar arquivo tar
Write-Host "[2/5] Criando pacote de deploy..." -ForegroundColor Yellow
$TarFile = "$TempDir\cloaker.tar"

Push-Location $TempDir
$tarOutput = tar -cf cloaker.tar * 2>&1
Pop-Location

if (-not (Test-Path $TarFile)) {
    Write-Host "[ERRO] Falha ao criar arquivo tar" -ForegroundColor Red
    exit 1
}

$TarSize = [math]::Round((Get-Item $TarFile).Length / 1KB, 2)
Write-Host "[OK] Pacote criado: $TarSize KB" -ForegroundColor Green

Write-Host ""
Write-Host "[3/5] Enviando arquivos para o servidor..." -ForegroundColor Yellow
Write-Host "      Isso pode demorar alguns segundos..." -ForegroundColor Gray
Write-Host ""
Write-Host ">>> QUANDO PEDIR A SENHA, DIGITE: $Password <<<" -ForegroundColor Magenta
Write-Host ""

# Upload do tar
& $ScpPath -o StrictHostKeyChecking=no "$TarFile" "${User}@${ServerIP}:/tmp/cloaker.tar"

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERRO] Falha no upload. Verifique a senha e conexão." -ForegroundColor Red
    Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "[OK] Upload concluído!" -ForegroundColor Green

Write-Host ""
Write-Host "[4/5] Executando setup no servidor..." -ForegroundColor Yellow
Write-Host "      Instalando Docker, configurando e iniciando cloaker..." -ForegroundColor Gray
Write-Host ""
Write-Host ">>> QUANDO PEDIR A SENHA NOVAMENTE, DIGITE: $Password <<<" -ForegroundColor Magenta
Write-Host ""

# Executar setup remoto
& $SshPath -o StrictHostKeyChecking=no "${User}@${ServerIP}" "cd /tmp && tar -xf cloaker.tar remote-setup.sh && chmod +x remote-setup.sh && ./remote-setup.sh"

if ($LASTEXITCODE -ne 0) {
    Write-Host "[AVISO] O script pode ter encontrado erros. Verifique a saída acima." -ForegroundColor Yellow
}

# Cleanup
Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[5/5] Verificando instalação..." -ForegroundColor Yellow

# Testar conexão com a API
Start-Sleep -Seconds 5

try {
    $response = Invoke-WebRequest -Uri "http://${ServerIP}:8081/api/v1/stats" -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
    if ($response.StatusCode -eq 200) {
        Write-Host "[OK] API respondendo corretamente!" -ForegroundColor Green
    }
} catch {
    Write-Host "[INFO] API pode estar ainda inicializando. Aguarde 1-2 minutos." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Green
Write-Host "              DEPLOY FINALIZADO!" -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard: http://${ServerIP}:8081" -ForegroundColor Cyan
Write-Host "  Proxy:     http://${ServerIP}" -ForegroundColor Cyan
Write-Host ""
Write-Host "  As credenciais foram exibidas no terminal acima." -ForegroundColor Yellow
Write-Host "  Também estão salvas em: /root/cloaker-credentials.txt no servidor" -ForegroundColor Gray
Write-Host ""
Write-Host "  Para ver as credenciais novamente, execute:" -ForegroundColor Gray
Write-Host "  ssh root@$ServerIP 'cat /root/cloaker-credentials.txt'" -ForegroundColor White
Write-Host ""

# Salvar info local
$InfoFile = Join-Path $CloakerDir "DEPLOY-INFO.txt"
@"
NEXUS Cloaker - Deploy Info
===========================
Data: $(Get-Date)
Servidor: $ServerIP

Dashboard: http://${ServerIP}:8081
Proxy: http://${ServerIP}

Para ver credenciais:
  ssh root@$ServerIP 'cat /root/cloaker-credentials.txt'
"@ | Out-File $InfoFile -Encoding UTF8

Write-Host "  Info salvo localmente em: $InfoFile" -ForegroundColor Gray

