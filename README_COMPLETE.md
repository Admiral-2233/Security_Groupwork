# SOCP v1.3 - Secure Overlay Chat Protocol Implementation

**Group Name:** [Your Group Name]
**Group Members:** [Member Names]
**Course:** Advanced Secure Programming
**Date:** October 2025

## Overview

This repository contains our implementation of the SOCP (Secure Overlay Chat Protocol) v1.3, a distributed end-to-end encrypted chat system with no central authority. The system supports user listing, private messaging, public channels, and file transfers through a peer-to-peer overlay network.

## Repository Structure

```
socp/
├── README.md                   # This file
├── reflective_commentary.md    # Detailed reflection on the project
├── requirements.txt            # Python dependencies
├── config.yaml                # Server configuration
│
├── clean/                     # Backdoor-free implementation
│   ├── server.py             # Clean server implementation
│   ├── client.py             # CLI client
│   └── gui_client.py         # GUI client
│
├── vulnerable/               # Implementation with intentional backdoors
│   ├── server_backdoored.py # Server with vulnerabilities
│   └── exploit_poc.py       # Proof of concept exploits
│
└── common/                   # Shared modules
    ├── common.py            # Utility functions
    ├── crypto_socp.py       # Cryptographic operations
    ├── envelope.py          # Message envelope handling
    └── db.py               # User database operations
```

## Installation

### Prerequisites
- Python 3.9 or higher
- Virtual environment (recommended)

### Setup Instructions

1. **Clone the repository:**
```bash
git clone [repository-url]
cd socp
```

2. **Create and activate virtual environment:**
```bash
python -m venv .venv

# On Windows:
.venv\Scripts\activate

# On Linux/Mac:
source .venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

### Dependencies
- `websockets==11.0.3` - WebSocket communication
- `pycryptodome==3.19.0` - Cryptographic operations
- `PyYAML==6.0.1` - Configuration file parsing
- `PySide6==6.5.2` - GUI framework (for gui_client.py)
- `qasync==0.24.1` - Qt async integration

## Running the Application

### Server Setup

1. **Configure the introducer node (port 9000):**
```yaml
# config.yaml
server:
  host: "0.0.0.0"
  port: 9000
  introducer: true
```

```bash
python server.py
```

2. **Configure a regular node (port 9001):**
```yaml
# config.yaml
server:
  host: "0.0.0.0"
  port: 9001
  introducer: false

bootstrap:
  - host: "127.0.0.1"
    port: 9000
    pubkey: ""
```

```bash
python server.py
```

### Client Usage

#### CLI Client
```bash
# Connect to server
python client.py <your-uuid-v4> ws://127.0.0.1:9000

# Available commands:
/list                    # List online users
/tell <user> <message>   # Send private message
/all <message>          # Send to public channel
/file <user> <filepath> # Send file
```

#### GUI Client
```bash
python gui_client.py
# Enter server URL: ws://127.0.0.1:9000
# Enter UUID: your-unique-id
# Click Connect
```

## Command Examples

### Starting a two-server network:
```bash
# Terminal 1 - Introducer
python server.py  # config: introducer=true, port=9000

# Terminal 2 - Regular node
python server.py  # config: introducer=false, port=9001

# Terminal 3 - Alice
python client.py alice-uuid ws://127.0.0.1:9000

# Terminal 4 - Bob
python client.py bob-uuid ws://127.0.0.1:9001
```

### Messaging example:
```
# In Alice's terminal:
/list
> Online: alice-uuid, bob-uuid

/tell bob-uuid Hello Bob!
> Message sent

/all Hello everyone!
> [Public] message sent

/file bob-uuid document.pdf
> File transfer initiated
```

## Security Features

- **End-to-End Encryption:** RSA-4096 OAEP with SHA-256
- **Digital Signatures:** RSASSA-PSS for message authentication
- **Overlay Routing:** Distributed architecture with no central authority
- **Message Deduplication:** Prevents replay attacks
- **Public Channels:** Group messaging with distributed key management

## Testing

### Interoperability Testing
Our implementation has been tested for interoperability with:
- Group Alpha's Python implementation
- Group Beta's Rust implementation
- Successfully exchanged messages across different implementations

### Test Scenarios
1. **User Registration:** Multiple users connecting to different servers
2. **Message Routing:** Messages correctly routed through overlay network
3. **Channel Operations:** Public channel key distribution and messaging
4. **File Transfer:** Large file chunking and encryption
5. **Failure Recovery:** Node disconnection and reconnection

## Known Issues and Limitations

1. **Performance:** RSA encryption for every message is computationally expensive
2. **Scalability:** In-memory storage limits server capacity
3. **Security:** No perfect forward secrecy
4. **Reliability:** No message persistence or delivery confirmation

## Troubleshooting

**Connection refused:**
- Ensure server is running on specified port
- Check firewall settings

**Signature verification failed:**
- Verify all nodes using same protocol version
- Check time synchronization between systems

**User not found:**
- Wait for presence propagation (few seconds)
- Use `/list` to verify user online status

## Version Information

- Protocol Version: SOCP v1.3
- Implementation Version: 1.0.0
- Python Version: 3.9+

## Academic Integrity Notice

This code is submitted as part of an academic assignment. The vulnerable version contains intentional security flaws for educational purposes only. DO NOT deploy the vulnerable version in any production environment.

## Contact

For questions about this implementation, please contact:
- [Your Email]
- [Group Member Emails]

## License

This project is for educational purposes only as part of the Advanced Secure Programming course.