#!/bin/bash

# Exit on error
set -e
echo "[*] Setting up AD Attack Framework..."

# Create and activate virtual environment
echo "[*] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Set PYTHONPATH to include the project root
export PYTHONPATH=$PYTHONPATH:$(pwd)

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

# Set up Neo4j for BloodHound
echo "[*] Setting up Neo4j..."
sudo systemctl enable neo4j
sudo systemctl start neo4j
sudo neo4j-admin set-initial-password bloodhound

echo "[+] Setup complete!"
echo "[+] The virtual environment is already activated."
echo "[+] You can now run the framework with: python src/main.py"