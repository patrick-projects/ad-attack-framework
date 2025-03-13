#!/bin/bash
# Exit on error
set -e
echo "[*] Setting up AD Attack Framework..."

# Create and activate virtual environment
echo "[*] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install required system packages
echo "[*] Installing system dependencies..."
sudo apt update
sudo apt install -y \
    python3-venv \
    responder \
    impacket-scripts \
    bloodhound

# Install Neo4j
echo "[*] Installing Neo4j..."
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/neo4j-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/neo4j-archive-keyring.gpg] https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt update
sudo apt install -y neo4j

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo "[*] Creating required directories..."
mkdir -p logs reports loot

# Ensure the src directory is in the Python path
echo "[*] Setting up Python path..."
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
echo "export PYTHONPATH=\$PYTHONPATH:$SCRIPT_DIR" >> venv/bin/activate

# Set up Neo4j for BloodHound
echo "[*] Setting up Neo4j..."
NEO4J_PASSWORD="bloodhound"
sudo systemctl enable neo4j
sudo systemctl start neo4j
sudo neo4j-admin dbms set-initial-password $NEO4J_PASSWORD

# Add a helper script to run the framework
echo "[*] Creating helper script..."
cat > run.sh << 'EOF'
#!/bin/bash
source venv/bin/activate
python src/main.py "$@"
EOF
chmod +x run.sh

# Start BloodHound in the background
echo "[*] Starting BloodHound..."
(bloodhound &>/dev/null &)

# Print out credentials and URLs
echo ""
echo "================================================================="
echo "                      SETUP COMPLETE                             "
echo "================================================================="
echo ""
echo "Neo4j Database Credentials:"
echo "  URL:      http://localhost:7474"
echo "  Username: neo4j"
echo "  Password: $NEO4J_PASSWORD"
echo ""
echo "BloodHound Credentials:"
echo "  Username: neo4j"
echo "  Password: $NEO4J_PASSWORD"
echo ""
echo "BloodHound has been started. However, you still need to collect AD information with creds."
echo ""
echo "To start the AD Attack Framework:"
echo "  ./run.sh"
echo ""
echo "If you open a new terminal, activate the environment first:"
echo "  source venv/bin/activate"
echo ""
echo "================================================================="

# Open Neo4j interface in browser
if command -v xdg-open &> /dev/null; then
    echo "[*] Opening Neo4j interface in your browser..."
    xdg-open http://localhost:7474 &>/dev/null &
fi