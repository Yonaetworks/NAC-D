apt update
apt install -y pip git
pip3 install pypsrp fastapi uvicorn
git clone https://github.com/Yonaetworks/NAC-D/tree/main/COMPLIANCE-API compliance
uvicorn compliance:app --reload --app-dir="$(pwd)/compliance"