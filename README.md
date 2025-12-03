# NEXUS Cloaker

Sistema de cloaking avançado para Meta Ads e TikTok Ads com detecção por IA, fingerprinting de última geração e dashboard em tempo real.

## 🚀 Features

- **Detecção por IA/ML** - Modelo de machine learning para identificar bots e revisores
- **Fingerprinting Avançado** - 13+ sinais: Canvas, WebGL, Audio, WebRTC, etc.
- **Detecção de VPN/Proxy** - WebRTC leak detection, ASN analysis
- **Zero-Touch Setup** - Só aponta DNS, sem modificar código/arquivos
- **Dashboard em Tempo Real** - Métricas, analytics, gestão de campanhas
- **Multi-domínio** - Domínios ilimitados com SSL automático
- **Webhooks** - Telegram, Discord, webhooks customizados
- **A/B Testing** - Split de tráfego configurável
- **Self-hosted** - Seus dados, seu controle total

## 📋 Requisitos

- VPS com pelo menos 1GB RAM (recomendado 2GB)
- Docker e Docker Compose
- Domínio apontando para o servidor (opcional, mas recomendado)

## 🛠️ Instalação Rápida

### 1. Na sua VPS (Ubuntu/Debian):

```bash
# Instalar Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Instalar Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Clonar/copiar o projeto
mkdir -p /opt/cloaker
cd /opt/cloaker
# (copie os arquivos para cá)

# Iniciar
docker-compose up -d
```

### 2. Acessar o Dashboard

- URL: `http://SEU_IP:8081`
- Usuário: `admin`
- Senha: `admin123`

**⚠️ IMPORTANTE: Altere a senha padrão após o primeiro login!**

## 📖 Como Usar

### 1. Criar uma Campanha

1. Acesse o Dashboard → Campanhas → Nova Campanha
2. Configure:
   - **Nome**: Identificação da campanha
   - **URL Safe**: Página exibida para bots/revisores
   - **URL Money**: Página exibida para humanos
   - **Split A/B**: Porcentagem de tráfego para cada página

### 2. Adicionar um Domínio

1. Acesse Domínios → Novo Domínio
2. Digite o domínio (ex: `oferta.seusite.com`)
3. Selecione a campanha associada

### 3. Configurar DNS

Aponte seu domínio para o IP do servidor:

```
Tipo: A
Nome: oferta (ou @ para raiz)
Valor: IP_DO_SEU_SERVIDOR
TTL: Auto
```

Ou usando Cloudflare (recomendado):
```
Tipo: A
Nome: oferta
Valor: IP_DO_SEU_SERVIDOR
Proxy: Ativado (nuvem laranja)
```

### 4. Pronto!

O sistema automaticamente:
- Detecta bots e revisores
- Injeta scripts de fingerprinting
- Redireciona para a página correta
- Registra todas as visitas

## 🔧 Configuração Avançada

### Editar `config.yaml`:

```yaml
server:
  port: 8080
  admin_port: 8081

detection:
  bot_score_threshold: 0.7  # Ajuste a sensibilidade

auth:
  jwt_secret: "GERE_UM_SECRET_SEGURO"
  admin_password: "SENHA_SEGURA"

webhooks:
  telegram:
    enabled: true
    bot_token: "SEU_BOT_TOKEN"
    chat_id: "SEU_CHAT_ID"
```

### Reiniciar após alterações:

```bash
docker-compose down
docker-compose up -d
```

## 🔒 SSL/HTTPS

### Opção 1: Cloudflare (Recomendado)

1. Adicione seu domínio no Cloudflare
2. Ative proxy (nuvem laranja)
3. SSL/TLS → Full

### Opção 2: Caddy (SSL automático)

```bash
docker-compose --profile ssl up -d
```

Edite o `Caddyfile` com seus domínios.

### Opção 3: Let's Encrypt manual

```bash
apt install certbot
certbot certonly --standalone -d seudominio.com
```

## 📊 API

### Autenticação

```bash
# Via API Key (no header)
curl -H "X-API-Key: SUA_API_KEY" http://localhost:8081/api/v1/stats

# Via JWT Token
curl -H "Authorization: Bearer SEU_TOKEN" http://localhost:8081/api/v1/stats
```

### Endpoints

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/v1/login` | Autenticar e obter token |
| GET | `/api/v1/stats` | Estatísticas gerais |
| GET/POST | `/api/v1/campaigns` | Listar/Criar campanhas |
| GET/PUT/DELETE | `/api/v1/campaigns/:id` | Gerenciar campanha |
| GET/POST | `/api/v1/domains` | Listar/Criar domínios |
| DELETE | `/api/v1/domains/:id` | Remover domínio |
| GET | `/api/v1/visits` | Listar visitas |
| GET/POST | `/api/v1/webhooks` | Gerenciar webhooks |

## 🤖 Sistema de Detecção

### Camada 1: Server-Side (< 1ms)
- IP em blacklist (Meta, TikTok, datacenters)
- ASN de hosting/VPN
- User-Agent de bots conhecidos
- TLS fingerprint

### Camada 2: Client-Side (< 10ms)
- Canvas fingerprint
- WebGL fingerprint
- Audio fingerprint
- Screen/Device info
- WebRTC leak (detecta VPN)
- Timezone/Language

### Camada 3: Machine Learning
- Score combinado de todos os sinais
- Threshold configurável
- Aprendizado contínuo

## 📱 Webhooks

### Telegram

1. Crie um bot com @BotFather
2. Obtenha o token do bot
3. Inicie uma conversa com o bot
4. Obtenha seu chat_id
5. Configure no dashboard ou `config.yaml`

### Discord

1. Server Settings → Integrations → Webhooks
2. Crie um webhook e copie a URL
3. Configure no dashboard

## 🔍 Troubleshooting

### Logs

```bash
# Ver logs
docker-compose logs -f

# Logs do cloaker
docker-compose logs -f cloaker
```

### Reiniciar

```bash
docker-compose restart
```

### Reconstruir

```bash
docker-compose down
docker-compose up -d --build
```

### Verificar status

```bash
docker-compose ps
```

## 📈 Performance

Métricas típicas em VPS de 2GB:
- **Latência**: < 10ms para decisão
- **Throughput**: 1000+ req/s
- **Memória**: ~200MB em idle
- **CPU**: < 5% em idle

## 🔐 Segurança

- [ ] Altere a senha padrão
- [ ] Use HTTPS (Cloudflare ou Let's Encrypt)
- [ ] Configure firewall (UFW)
- [ ] Restrinja acesso ao dashboard por IP
- [ ] Faça backup regular do banco de dados

```bash
# Backup do banco
docker-compose exec cloaker cat /app/data/db/cloaker.db > backup.db
```

## 📄 Licença

Este projeto é para uso pessoal/educacional. Use com responsabilidade.

## 🆘 Suporte

- Issues no GitHub
- Documentação da API
- Logs de erro

---

**NEXUS Cloaker** - O sistema de cloaking mais avançado do mercado.

