#!/bin/bash
# CHRONOS Installation Script
# Complete setup for production deployment

set -e

echo "======================================"
echo "CHRONOS Installation & Setup Script"
echo "======================================"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Step 1: Check prerequisites
echo ""
log_info "Step 1: Checking prerequisites..."

which python3 > /dev/null 2>&1 || { log_error "Python 3 not found"; exit 1; }
log_info "✓ Python 3 found: $(python3 --version)"

which docker > /dev/null 2>&1 || { log_warn "Docker not found - containers won't run"; }
which docker-compose > /dev/null 2>&1 || { log_warn "docker-compose not found"; }

# Step 2: Create directories
echo ""
log_info "Step 2: Creating required directories..."

mkdir -p models
mkdir -p logs
mkdir -p data/collectors/cloud
mkdir -p data/collectors/linux
mkdir -p data/collectors/windows
mkdir -p data/collectors/network
mkdir -p config

log_info "✓ Directories created"

# Step 3: Install Python dependencies
echo ""
log_info "Step 3: Installing Python dependencies..."

log_info "Installing minimal required packages (this may take a few minutes)..."
pip install --upgrade pip setuptools wheel > /dev/null 2>&1

# Install critical packages
PACKAGES=(
    "pyyaml>=6.0"
    "python-dotenv>=1.0.0"
    "pandas>=2.0.0"
    "numpy>=1.24.0"
    "scipy>=1.10.0"
    "elasticsearch>=8.0.0"
    "neo4j>=5.0.0"
    "kafka-python>=2.0.2"
    "redis>=4.5.0"
    "fastapi>=0.100.0"
    "uvicorn>=0.23.0"
    "websockets>=11.0.0"
    "requests>=2.31.0"
    "scikit-learn>=1.3.0"
    "cryptography>=39.0.0"
    "python-nmap>=0.7.1"
)

for package in "${PACKAGES[@]}"; do
    log_info "Installing: $package"
    pip install "$package" > /dev/null 2>&1 || log_warn "Could not install $package"
done

log_info "✓ Python dependencies installed"

# Optional: PyTorch (CPU only)
echo ""
log_warn "PyTorch required for ML models. Install it? (requires ~500MB) [y/N]"
read -r -t 10 torch_response || torch_response="N"

if [[ "$torch_response" =~ ^[Yy]$ ]]; then
    log_info "Installing PyTorch (CPU version)..."
    pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu > /dev/null 2>&1
    log_info "✓ PyTorch installed"
else
    log_warn "Skipped PyTorch installation"
fi

# Step 4: Setup environment file
echo ""
log_info "Step 4: Setting up environment configuration..."

if [ ! -f "config/.env" ]; then
    if [ -f "config/.env.example" ]; then
        cp config/.env.example config/.env
        log_info "✓ Created config/.env from template"
        log_warn "Please edit config/.env with your API keys"
    else
        log_error "config/.env.example not found"
    fi
else
    log_info "✓ config/.env already exists"
fi

# Step 5: Create ML models
echo ""
log_warn "Create placeholder ML models now? [Y/n]"
read -r -t 10 model_response || model_response="Y"

if [[ ! "$model_response" =~ ^[Nn]$ ]]; then
    log_info "Creating placeholder ML models..."
    if python3 create_placeholder_models.py; then
        log_info "✓ ML models created successfully"
    else
        log_warn "Failed to create ML models - continuing anyway"
    fi
else
    log_info "Skipped ML model creation"
fi

# Step 6: Fix file permissions
echo ""
log_info "Step 5: Fixing file permissions..."

chmod +x create_placeholder_models.py 2>/dev/null || true
chmod +x scripts/run.py 2>/dev/null || true

log_info "✓ Permissions fixed"

# Step 7: Docker services
echo ""
log_warn "Start Docker services? [Y/n]"
read -r -t 10 docker_response || docker_response="Y"

if [[ ! "$docker_response" =~ ^[Nn]$ ]]; then
    if command -v docker-compose &> /dev/null; then
        log_info "Starting Docker services..."
        docker-compose up -d
        log_info "✓ Docker services started"
        
        log_info "Waiting for services to be healthy (60 seconds)..."
        sleep 60
        
        # Verify services
        log_info "Verifying services..."
        
        if curl -s http://localhost:9200/_cluster/health > /dev/null 2>&1; then
            log_info "✓ Elasticsearch is responding"
        else
            log_warn "⚠ Elasticsearch not responding yet"
        fi
        
        if docker exec chronos-kafka kafka-broker-api-versions --bootstrap-server kafka:9092 > /dev/null 2>&1; then
            log_info "✓ Kafka is responding"
        else
            log_warn "⚠ Kafka not responding yet"
        fi
    else
        log_warn "docker-compose not found - skipping Docker services"
    fi
else
    log_info "Skipped Docker startup"
fi

# Step 8: Create Elasticsearch indices
echo ""
log_warn "Initialize Elasticsearch indices? [Y/n]"
read -r -t 10 indices_response || indices_response="Y"

if [[ ! "$indices_response" =~ ^[Nn]$ ]]; then
    log_info "Creating Elasticsearch indices..."
    
    curl -s -X PUT http://localhost:9200/chronos-events \
        -H "Content-Type: application/json" \
        -d '{"settings":{"number_of_shards":1,"number_of_replicas":0}}' \
        > /dev/null 2>&1 && log_info "✓ chronos-events index created" \
        || log_warn "⚠ Could not create chronos-events index"
    
    curl -s -X PUT http://localhost:9200/chronos-alerts \
        -H "Content-Type: application/json" \
        -d '{"settings":{"number_of_shards":1,"number_of_replicas":0}}' \
        > /dev/null 2>&1 && log_info "✓ chronos-alerts index created" \
        || log_warn "⚠ Could not create chronos-alerts index"
else
    log_info "Skipped Elasticsearch index creation"
fi

# Step 9: Verification
echo ""
log_info "Step 6: Verification and Status"

log_info "Checking Python packages..."
python3 -c "import pandas; print('✓ pandas')" 2>/dev/null || log_warn "pandas not available"
python3 -c "import elasticsearch; print('✓ elasticsearch')" 2>/dev/null || log_warn "elasticsearch not available"
python3 -c "import kafka; print('✓ kafka')" 2>/dev/null || log_warn "kafka not available"
python3 -c "import neo4j; print('✓ neo4j')" 2>/dev/null || log_warn "neo4j not available"
python3 -c "import fastapi; print('✓ fastapi')" 2>/dev/null || log_warn "fastapi not available"

# Summary
echo ""
echo "======================================"
echo -e "${GREEN}Installation Complete!${NC}"
echo "======================================"
echo ""
echo "Next Steps:"
echo "1. Edit config/.env with your API keys and credentials"
echo "2. Configure data sources (Sysmon, Zeek, CloudTrail)"
echo "3. Train ML models with real detection data"
echo "4. Start the detection engine: python -m chronos.scripts.run engine"
echo "5. Start the API server: python -m chronos.scripts.run api"
echo "6. Access the UI at http://localhost:80"
echo ""
echo "Documentation: See SETUP_GUIDE.md for detailed instructions"
echo ""
