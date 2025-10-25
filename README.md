

# SOCP v1.3 - Secure Overlay Chat Protocol

## Project Overview

SOCP (Secure Overlay Chat Protocol) v1.3 is a distributed end-to-end encrypted chat system that adopts a peer-to-peer network architecture without central authority. The system supports user lists, private messages, public channels, and file transfers through a peer overlay network, designed for advanced security programming courses.

### Core Features
- **End-to-end encryption**: Uses RSA-4096 OAEP encryption and RSASSA-PSS digital signatures
- **Distributed architecture**: Peer-to-peer network without central authority, supporting multi-server interconnection
- **User management**: User registration, online status management, and user list functionality
- **Message delivery**: Supports private messages and public channel messages
- **File transfer**: Chunked encrypted file transfer functionality
- **Multiple clients**: Supports both command-line interface and graphical user interface clients

## System Architecture

### Network Topology
```
┌─────────────────┐    ┌─────────────────┐
│   Client A      │    │   Client B      │
│  (CLI/GUI)      │    │  (CLI/GUI)      │
└────────┬────────┘    └────────┬────────┘
         │                       │
         │                       │
    ┌────┴────┐              ┌────┴────┐
    │ Server 1 │              │ Server 2 │
    │ Port 9000│◄─────────────┤ Port 9001│
    │Introducer│              │ Normal   │
    └─────────┘              └─────────┘
```

### Message Flow Architecture
- **User connection**: Handshake through USER_HELLO messages
- **Message routing**: Servers exchange routing information through SERVER_ANNOUNCE and USER_ADVERTISE messages
- **End-to-end encryption**: Message content is encrypted throughout, servers only handle routing
- **Digital signatures**: All messages are verified through digital signatures

## Detailed Deployment Guide

### Environment Preparation

#### System Requirements
- **Operating System**: Windows 10/11, Linux, macOS
- **Python Version**: Python 3.9 or higher
- **Memory Requirements**: Minimum 512MB, recommended 1GB+
- **Network Requirements**: Open ports 9000-9010 (configurable)

#### Dependency Installation
```bash
# 1. Create virtual environment
python -m venv .venv

# 2. Activate virtual environment (Windows)
.venv\Scripts\activate

# 3. Activate virtual environment (Linux/Mac)
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

#### Detailed Dependency Description
- **PySide6==6.7.2**: Qt GUI framework for graphical interface clients
- **qasync==0.24.0**: Qt async integration to ensure GUI doesn't freeze
- **websockets==12.0**: WebSocket communication library for handling real-time connections
- **PyYAML==6.0.2**: YAML configuration file parsing
- **pycryptodome==3.20.0**: Cryptographic operations library providing RSA algorithm support

### Server Deployment

#### Introducer Node Deployment (Port 9000)
```bash
# 1. Configure introducer node
cp config_introducer.yaml config.yaml

# 2. Edit configuration file (optional)
# config.yaml content:
server:
  host: "0.0.0.0"    # Listen on all network interfaces
  port: 9000         # Introducer node port
  introducer: true     # Mark as introducer node

bootstrap:
  - host: "127.0.0.1"
    port: 9000
    pubkey: ""

# 3. Start server
python server.py
```

#### Normal Node Deployment (Port 9001)
```bash
# 1. Configure normal node
cp config_normal.yaml config.yaml

# 2. Edit configuration file:
server:
  host: "0.0.0.0"
  port: 9001         # Normal node port
  introducer: false  # Mark as normal node

bootstrap:
  - host: "127.0.0.1"
    port: 9000       # Point to introducer node
    pubkey: ""

# 3. Start server
python server.py
```

#### Production Environment Deployment
```bash
# 1. Using systemd service (Linux)
sudo nano /etc/systemd/system/socp-server.service

[Unit]
Description=SOCP Server
After=network.target

[Service]
Type=simple
User=socp
WorkingDirectory=/opt/socp
ExecStart=/opt/socp/.venv/bin/python server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target

# 2. Enable service
sudo systemctl enable socp-server
sudo systemctl start socp-server
```

### Client Deployment

#### Command Line Client
```bash
# 1. Generate user UUID
python -c "import uuid; print(uuid.uuid4())"

# 2. Connect to server
python client.py <your-UUID-v4> ws://127.0.0.1:9000

# 3. Available commands:
/list                    # List online users
/tell <user> <message>   # Send private message
/all <message>           # Send to public channel
/file <user> <file_path> # Send file
/help                    # Show help information
```

#### Graphical User Interface Client
```bash
# 1. Start GUI client
python gui_client.py

# 2. Enter connection information:
# - Server URL: ws://127.0.0.1:9000
# - User UUID: Your unique identifier
# - Click connect button

# 3. Use interface features:
# - Left: Online user list
# - Middle: Message display area
# - Bottom: Message input box
# - Top: Connection status indicator
```

#### Demo Script for Quick Testing
```bash
# Run simplified demo (automatically create two clients and exchange messages)
python demo_simple.py

# Output example:
# 🎭 SOCP System Simplified Demo
# ========================================
# 🔄 alice-demo connecting to ws://127.0.0.1:9000...
# 🔄 bob-demo connecting to ws://127.0.0.1:9000...
# ✅ alice-demo connected successfully!
# ✅ bob-demo connected successfully!
# 👥 alice-demo online users: ['alice-demo', 'bob-demo']
# 👥 bob-demo online users: ['alice-demo', 'bob-demo']
# 📤 alice-demo -> bob-demo: Hello Bob! 👋
# 💬 bob-demo received message from alice-demo: Hello Bob! 👋
# 📤 bob-demo -> alice-demo: Hi Alice! 😊
# 💬 alice-demo received message from bob-demo: Hi Alice! 😊
# 🎉 Demo completed!
```

## Security Architecture Analysis

### Detailed Encryption Mechanism
```python
# RSA-4096 OAEP encryption process
Message -> RSA-OAEP encryption -> Base64URL encoding -> Network transmission

# Digital signature process
Message content + timestamp + sender ID -> RSASSA-PSS signature -> Base64URL encoding

# Key exchange process
1. User generates RSA-4096 key pair
2. Send public key in USER_HELLO message
3. Server stores user public key to users.json
4. Subsequent messages use target user's public key for encryption
```

### Message Integrity Verification
- **Envelope signature**: Verify message source and integrity
- **Content signature**: Verify message content has not been tampered with
- **Timestamp verification**: Prevent replay attacks (5-second window)
- **UUID verification**: Ensure user identity uniqueness

### Security Threat Model
1. **Passive attacks**: Network monitoring, traffic analysis
2. **Active attacks**: Message forgery, replay attacks, man-in-the-middle attacks
3. **Server compromise**: Server is attacked but message content remains encrypted
4. **Client attacks**: Key leakage, malware infection

## Backdoor and Vulnerability Analysis

### Educational Backdoor Implementation

#### Backdoor #1: Debug Mode Bypass
```python
# Debug mode implemented in server.py
# Trigger condition: meta field in USER_HELLO message contains specific string
if "debug" in str(env.get("payload", {}).get("meta", "")).lower():
    self.debug_mode = True
    
# Effect: Bypass signature verification, allow execution of debug commands
```

**Exploitation Method:**
```bash
# Send specially crafted USER_HELLO message
# Include "debug" string in meta field
# Server will activate debug mode, bypassing normal verification
```

#### Backdoor #2: Command Injection Vulnerability
```python
# Command injection implemented in server_backdoored.py
# When debug_mode is activated, /debug command can execute system commands
elif cmd == "/debug" and self.debug_mode:
    import subprocess
    result = subprocess.run(args, shell=True, capture_output=True, text=True)
```

**Exploitation Method:**
```bash
# First activate debug mode
# Then send: /debug whoami
# Server will execute whoami command and return result
```

#### Backdoor #3: Replay Attack Window
```python
# Modified duplicate message detection mechanism
# Originally should permanently store message hash, but changed to clear after 5 seconds
deduplication_window = 5  # seconds
# Allows attacker to replay messages from 5 seconds ago
```

**Exploitation Method:**
```bash
# Intercept legitimate message
# Wait for 5-second replay window to end
# Replay same message, server will accept as valid message
```

### Privilege Escalation Techniques

#### File System Access
```bash
# Access server file system through file transfer functionality
/file admin /etc/passwd
# May leak sensitive system files

# Path traversal attack attempt
/file admin ../../../etc/passwd
# Try to access parent directory
```

#### User Permission Bypass
```python
# Potential vulnerabilities in verification logic
# Some implementations may allow UUID prediction or enumeration
for i in range(1000):
    test_uuid = f"user-{i:03d}"
    # Try to connect and get user information
```

### Defensive Measures Recommendations

#### Input Validation Enhancement
```python
# Strict input validation
def validate_user_id(user_id):
    import re
    # UUID v4 format validation
    pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    return re.match(pattern, user_id.lower()) is not None
```

#### Security Logging
```python
# Comprehensive security event logging
import logging
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

# Log all connection attempts
security_logger.info(f"Connection attempt from {client_ip}: {user_id}")
# Log all command executions
security_logger.warning(f"Command executed: {command} by {user_id}")
```

#### Network Layer Security
```yaml
# Using reverse proxy and SSL/TLS
nginx_config:
  server:
    listen 443 ssl;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    location /ws {
      proxy_pass http://localhost:9000;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
    }
```

## Performance Optimization

### Server Performance Tuning
```python
# Asynchronous processing optimization
import asyncio
from asyncio import Semaphore

# Limit concurrent connections
MAX_CONNECTIONS = 100
connection_semaphore = Semaphore(MAX_CONNECTIONS)

async def handle_client(websocket, path):
    async with connection_semaphore:
        # Handle client connection
        pass
```

### Memory Management
```python
# Periodically clean up expired data
async def cleanup_task():
    while True:
        await asyncio.sleep(300)  # Clean up every 5 minutes
        # Clean up expired messages
        # Clean up inactive users
        # Release memory
```

## Monitoring and Operations

### Health Check
```bash
# Server health check script
#!/bin/bash
# health_check.sh

PORT=${1:-9000}
if netstat -an | grep -q ":$PORT.*LISTEN"; then
    echo "Server is running on port $PORT"
    exit 0
else
    echo "Server is not responding on port $PORT"
    exit 1
fi
```

### Performance Monitoring
```python
# Integrated monitoring metrics
import time
import psutil

class MetricsCollector:
    def __init__(self):
        self.start_time = time.time()
        self.message_count = 0
        self.connection_count = 0
    
    def get_metrics(self):
        return {
            'uptime': time.time() - self.start_time,
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'message_count': self.message_count,
            'connection_count': self.connection_count
        }
```

## Advanced Troubleshooting Guide

### Connection Problem Diagnosis
```bash
# 1. Check port listening
netstat -an | findstr :9000

# 2. Test WebSocket connection
python -c "
import asyncio, websockets
async def test():
    try:
        async with websockets.connect('ws://127.0.0.1:9000') as ws:
            print('Connection successful')
    except Exception as e:
        print(f'Connection failed: {e}')
asyncio.run(test())
"

# 3. Check firewall settings
netsh advfirewall show allprofiles state
```

### Encryption Problem Diagnosis
```bash
# Check key file
openssl rsa -in user.pem -check -noout

# Verify certificate format
python -c "
from Crypto.PublicKey import RSA
key = RSA.import_key(open('user.pem').read())
print(f'Key size: {key.size_in_bits()} bits')
print(f'Can encrypt: {key.has_private()}')
"
```

### Performance Problem Diagnosis
```bash
# Monitor resource usage
tasklist /FI "IMAGENAME eq python.exe"

# Check memory leaks
python -c "
import tracemalloc, time
tracemalloc.start()
# Run for a period of time
snapshot1 = tracemalloc.take_snapshot()
time.sleep(10)
snapshot2 = tracemalloc.take_snapshot()
top_stats = snapshot2.compare_to(snapshot1, 'lineno')
print('[ Top 10 differences ]')
for stat in top_stats[:10]:
    print(stat)
"
```

## Legal and Compliance

### Terms of Use
- This system is for educational and research purposes only
- Must not be used for illegal activities or malicious purposes
- Users should comply with local laws and regulations
- System developers are not responsible for misuse

### Privacy Protection
- End-to-end encryption ensures message privacy
- Servers do not store message content
- User public keys are public, private keys are stored locally
- Comply with data protection regulations

### Security Disclosure
If you discover security vulnerabilities, please report them through the following methods:
- Send email to: security@example.com
- Provide detailed vulnerability description and reproduction steps
- Allow reasonable time for fixes before public disclosure

---

**Note**: This README contains technical details and security analysis for educational purposes only. For actual deployment, please configure security according to specific needs.