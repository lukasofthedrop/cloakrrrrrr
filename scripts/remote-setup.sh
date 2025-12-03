#!/bin/bash
# =============================================================================
# NEXUS Cloaker - Remote Setup Script (executa no servidor)
# =============================================================================
set -e

echo "=============================================="
echo "   NEXUS CLOAKER - SETUP AUTOMATIZADO"
echo "=============================================="
echo ""

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Variáveis
INSTALL_DIR="/opt/cloaker"
ADMIN_PASS=$(openssl rand -base64 12 | tr -d '=+/')
JWT_SECRET=$(openssl rand -hex 32)

echo -e "${YELLOW}[1/7] Parando serviços antigos...${NC}"
# Parar serviços web antigos
systemctl stop apache2 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true
systemctl stop mysql 2>/dev/null || true
systemctl disable apache2 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true
systemctl disable mysql 2>/dev/null || true

# Parar containers Docker antigos
docker stop $(docker ps -aq) 2>/dev/null || true
docker rm $(docker ps -aq) 2>/dev/null || true

echo -e "${GREEN}[✓] Serviços antigos parados${NC}"

echo -e "${YELLOW}[2/7] Instalando Docker...${NC}"
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    systemctl enable docker
    systemctl start docker
fi
echo -e "${GREEN}[✓] Docker instalado${NC}"

echo -e "${YELLOW}[3/7] Instalando Docker Compose...${NC}"
if ! command -v docker-compose &> /dev/null; then
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi
echo -e "${GREEN}[✓] Docker Compose instalado${NC}"

echo -e "${YELLOW}[4/7] Preparando diretórios...${NC}"
rm -rf $INSTALL_DIR 2>/dev/null || true
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR
echo -e "${GREEN}[✓] Diretórios preparados${NC}"

echo -e "${YELLOW}[5/7] Extraindo arquivos do cloaker...${NC}"
if [ -f /tmp/cloaker.tar ]; then
    tar -xf /tmp/cloaker.tar -C $INSTALL_DIR
    rm /tmp/cloaker.tar
    echo -e "${GREEN}[✓] Arquivos extraídos${NC}"
else
    echo -e "${RED}[✗] Arquivo /tmp/cloaker.tar não encontrado!${NC}"
    exit 1
fi

echo -e "${YELLOW}[6/7] Configurando segurança...${NC}"
cd $INSTALL_DIR

# Atualizar config.yaml com valores seguros
if [ -f config.yaml ]; then
    sed -i "s/CHANGE-THIS-TO-A-SECURE-RANDOM-STRING/$JWT_SECRET/" config.yaml
    sed -i "s/admin123/$ADMIN_PASS/" config.yaml
fi
echo -e "${GREEN}[✓] Configurações de segurança aplicadas${NC}"

echo -e "${YELLOW}[7/7] Iniciando containers...${NC}"
cd $INSTALL_DIR
docker-compose up -d --build

# Aguardar inicialização
echo "Aguardando containers iniciarem..."
sleep 15

# Verificar status
docker-compose ps

echo ""
echo "=============================================="
echo -e "${GREEN}   INSTALAÇÃO CONCLUÍDA COM SUCESSO!${NC}"
echo "=============================================="
echo ""
echo "  Dashboard: http://$(curl -s ifconfig.me 2>/dev/null || echo 'SEU_IP'):8081"
echo "  Proxy:     http://$(curl -s ifconfig.me 2>/dev/null || echo 'SEU_IP'):80"
echo ""
echo "  ╔═══════════════════════════════════════╗"
echo "  ║  CREDENCIAIS DE ACESSO                ║"
echo "  ╠═══════════════════════════════════════╣"
echo "  ║  Usuário: admin                       ║"
echo -e "  ║  Senha:   ${GREEN}$ADMIN_PASS${NC}              ║"
echo "  ╚═══════════════════════════════════════╝"
echo ""
echo -e "${RED}  ⚠️  ANOTE ESTA SENHA! Ela não será mostrada novamente.${NC}"
echo ""

# Salvar credenciais em arquivo
echo "NEXUS Cloaker - Credenciais" > /root/cloaker-credentials.txt
echo "=========================" >> /root/cloaker-credentials.txt
echo "Usuario: admin" >> /root/cloaker-credentials.txt
echo "Senha: $ADMIN_PASS" >> /root/cloaker-credentials.txt
echo "JWT Secret: $JWT_SECRET" >> /root/cloaker-credentials.txt
echo "" >> /root/cloaker-credentials.txt
echo "Dashboard: http://$(curl -s ifconfig.me 2>/dev/null):8081" >> /root/cloaker-credentials.txt
chmod 600 /root/cloaker-credentials.txt

echo "Credenciais também salvas em: /root/cloaker-credentials.txt"

