# Update and install venv support
apt update && apt install python3-venv -y

# Navigate to your project
cd ~/ad-attack-framework

# Create and activate venv
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Test your tool here
# e.g., python your_script.py


sudo apt install -y bloodhound neo4j responder impacket-scripts

python3 src/main.py


# Exit when done - commented out to not break setup script
# deactivate