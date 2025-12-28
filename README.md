```bash
apt update
apt install -y pipx
pipx ensurepath

pipx install streamlit
pipx inject streamlit requests

curl -fsSL https://sing-box.app/install.sh | sh

streamlit run app.py

