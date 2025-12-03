#!/bin/bash
# =============================================================================
# NEXUS Cloaker - Deploy Script for DigitalOcean
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DROPLET_NAME="nexus-cloaker"
REGION="nyc1"
SIZE="s-1vcpu-2gb"
IMAGE="docker-20-04"

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              NEXUS CLOAKER - DEPLOYMENT SCRIPT                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if doctl is installed
if ! command -v doctl &> /dev/null; then
    echo -e "${RED}[ERROR] doctl CLI not found. Installing...${NC}"
    echo ""
    echo "Please install doctl first:"
    echo "  - Windows: scoop install doctl OR winget install doctl"
    echo "  - Mac: brew install doctl"
    echo "  - Linux: snap install doctl"
    echo ""
    echo "Then authenticate: doctl auth init"
    exit 1
fi

# Check if authenticated
if ! doctl account get &> /dev/null; then
    echo -e "${YELLOW}[INFO] Not authenticated. Please run: doctl auth init${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] doctl authenticated${NC}"

# Function to create droplet
create_droplet() {
    echo -e "${BLUE}[INFO] Creating DigitalOcean Droplet...${NC}"
    
    # Generate SSH key if not exists
    if [ ! -f ~/.ssh/id_rsa.pub ]; then
        echo -e "${YELLOW}[INFO] Generating SSH key...${NC}"
        ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
    fi

    # Check if SSH key exists in DO
    SSH_KEY_ID=$(doctl compute ssh-key list --format ID,Name --no-header | grep "nexus-key" | awk '{print $1}')
    
    if [ -z "$SSH_KEY_ID" ]; then
        echo -e "${YELLOW}[INFO] Adding SSH key to DigitalOcean...${NC}"
        SSH_KEY_ID=$(doctl compute ssh-key create nexus-key --public-key "$(cat ~/.ssh/id_rsa.pub)" --format ID --no-header)
    fi

    echo -e "${BLUE}[INFO] SSH Key ID: $SSH_KEY_ID${NC}"

    # Create the droplet
    echo -e "${BLUE}[INFO] Creating droplet '$DROPLET_NAME' in $REGION...${NC}"
    
    DROPLET_ID=$(doctl compute droplet create "$DROPLET_NAME" \
        --region "$REGION" \
        --size "$SIZE" \
        --image "$IMAGE" \
        --ssh-keys "$SSH_KEY_ID" \
        --tag-name "cloaker" \
        --wait \
        --format ID \
        --no-header)

    echo -e "${GREEN}[✓] Droplet created! ID: $DROPLET_ID${NC}"

    # Get droplet IP
    sleep 5
    DROPLET_IP=$(doctl compute droplet get "$DROPLET_ID" --format PublicIPv4 --no-header)
    
    echo -e "${GREEN}[✓] Droplet IP: $DROPLET_IP${NC}"
    echo ""
    echo -e "${YELLOW}Waiting for droplet to be ready...${NC}"
    sleep 30

    # Deploy the application
    deploy_app "$DROPLET_IP"
}

# Function to deploy application to existing server
deploy_app() {
    local SERVER_IP=$1

    if [ -z "$SERVER_IP" ]; then
        echo -e "${YELLOW}Enter your server IP:${NC}"
        read SERVER_IP
    fi

    echo -e "${BLUE}[INFO] Deploying to $SERVER_IP...${NC}"

    # Create deployment directory
    ssh -o StrictHostKeyChecking=no root@"$SERVER_IP" << 'ENDSSH'
        # Update system
        apt-get update && apt-get upgrade -y

        # Install Docker if not present
        if ! command -v docker &> /dev/null; then
            curl -fsSL https://get.docker.com -o get-docker.sh
            sh get-docker.sh
            rm get-docker.sh
        fi

        # Install Docker Compose if not present
        if ! command -v docker-compose &> /dev/null; then
            curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            chmod +x /usr/local/bin/docker-compose
        fi

        # Create app directory
        mkdir -p /opt/cloaker
        cd /opt/cloaker
ENDSSH

    # Copy files to server
    echo -e "${BLUE}[INFO] Copying files to server...${NC}"
    
    # Create a tarball of the cloaker directory
    tar -czf /tmp/cloaker.tar.gz -C "$(dirname "$0")/.." .
    
    scp -o StrictHostKeyChecking=no /tmp/cloaker.tar.gz root@"$SERVER_IP":/opt/cloaker/
    rm /tmp/cloaker.tar.gz

    # Extract and start
    ssh -o StrictHostKeyChecking=no root@"$SERVER_IP" << 'ENDSSH'
        cd /opt/cloaker
        tar -xzf cloaker.tar.gz
        rm cloaker.tar.gz

        # Generate secure JWT secret
        JWT_SECRET=$(openssl rand -hex 32)
        sed -i "s/CHANGE-THIS-TO-A-SECURE-RANDOM-STRING/$JWT_SECRET/" config.yaml

        # Build and start
        docker-compose up -d --build

        # Show status
        echo ""
        echo "========================================"
        echo "  NEXUS CLOAKER DEPLOYED SUCCESSFULLY!"
        echo "========================================"
        docker-compose ps
ENDSSH

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              DEPLOYMENT COMPLETE!                             ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BLUE}Dashboard:${NC} http://$SERVER_IP:8081"
    echo -e "  ${BLUE}Proxy:${NC}     http://$SERVER_IP"
    echo ""
    echo -e "  ${YELLOW}Default credentials:${NC}"
    echo -e "    Username: admin"
    echo -e "    Password: admin123"
    echo ""
    echo -e "  ${RED}⚠️  IMPORTANT: Change the default password after first login!${NC}"
    echo ""
}

# Function to show menu
show_menu() {
    echo ""
    echo "What would you like to do?"
    echo ""
    echo "  1) Create new DigitalOcean Droplet and deploy"
    echo "  2) Deploy to existing server"
    echo "  3) Update existing deployment"
    echo "  4) View deployment status"
    echo "  5) Exit"
    echo ""
    echo -n "Choose an option [1-5]: "
    read choice

    case $choice in
        1) create_droplet ;;
        2) deploy_app ;;
        3) 
            echo "Enter server IP:"
            read ip
            deploy_app "$ip"
            ;;
        4)
            echo "Enter server IP:"
            read ip
            ssh root@"$ip" "cd /opt/cloaker && docker-compose ps && docker-compose logs --tail=50"
            ;;
        5) exit 0 ;;
        *) echo "Invalid option"; show_menu ;;
    esac
}

# Main
if [ "$1" == "--create" ]; then
    create_droplet
elif [ "$1" == "--deploy" ] && [ -n "$2" ]; then
    deploy_app "$2"
else
    show_menu
fi

