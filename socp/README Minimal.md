# SOCP v1.3 Minimal (MUST-compliant)

## Install
python -m venv .venv && . .venv/Scripts/activate
pip install -r requirements.txt

## Run servers
# Terminal 1 (introducer, :9000)
edit config.yaml -> introducer=true, port=9000
python server.py
# Terminal 2 (normal, :9001)
edit config.yaml -> introducer=false, port=9001, bootstrap points to 9000
python server.py

## Run clients
python client.py <alice-uuid-v4> ws://127.0.0.1:9000
python client.py <bob-uuid-v4>   ws://127.0.0.1:9001

## Commands
/list
/tell <user> <text>      # DM: RSA-OAEP + RSASSA-PSS(content_sig)
/all <text>              # Public channel: encrypt under channel pubkey
/file <user> <path>      # Manifest + RSA-encrypted chunks
