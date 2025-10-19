# SUBMISSION CHECKLIST - SOCP Assignment

## 📋 Files to Submit

### 1. Code Files
- [x] **Clean Version** (backdoor-free):
  - `server.py` - Original clean server implementation
  - `client.py` - CLI client
  - `gui_client.py` - GUI client (optional but recommended)

- [x] **Vulnerable Version** (with backdoors):
  - `server_backdoored.py` - Server with 3 intentional vulnerabilities

- [x] **Exploit Proof of Concept**:
  - `exploit_poc.py` - Demonstrates how to exploit the backdoors

- [x] **Supporting Files**:
  - `common.py` - Utility functions
  - `crypto_socp.py` - Cryptographic operations
  - `envelope.py` - Message envelope handling
  - `db.py` - Database operations
  - `config.yaml` - Configuration file
  - `requirements.txt` - Python dependencies

### 2. Documentation
- [x] **README.md** - Installation and usage instructions
- [x] **reflective_commentary.md** - Main submission document (under 2000 words)

## 🔒 Backdoor Summary

### Backdoor #1: Timing Attack (Replay Vulnerability)
- **Location:** `server_backdoored.py` lines 96-104
- **Mechanism:** Weak deduplication with 5-second window
- **Exploit:** Messages can be replayed after window expires

### Backdoor #2: Debug Mode
- **Location:** `server_backdoored.py` lines 136-140, 195-198
- **Trigger:** Special meta field in USER_HELLO: `{"debug_key": "d3bug_m0d3_3nabl3d"}`
- **Effect:** Bypasses signature verification

### Backdoor #3: Command Injection
- **Location:** `server_backdoored.py` lines 253-262
- **Activation:** `/debug <command>` when debug mode is active
- **Risk:** Remote code execution on server

## 📝 Pre-Submission Checklist

### Code Quality
- [ ] All files include group name and member names in headers
- [ ] Code is properly commented
- [ ] No actual malicious code (only ethical backdoors)
- [ ] Clean version has NO backdoors
- [ ] Vulnerable version clearly marked as such

### Documentation
- [ ] Reflective commentary is under 2000 words (main body)
- [ ] All 5 required sections present
- [ ] Group member contributions with percentages
- [ ] README has clear installation instructions
- [ ] Command examples provided

### Testing Evidence
- [ ] Screenshots of working implementation
- [ ] Proof of interoperability with other groups
- [ ] Exploit demonstration screenshots

## 📦 Submission Structure

```
submission/
├── clean/
│   ├── server.py
│   ├── client.py
│   ├── gui_client.py
│   └── [supporting files]
│
├── vulnerable/
│   ├── server_backdoored.py
│   └── exploit_poc.py
│
├── docs/
│   ├── reflective_commentary.md
│   ├── README.md
│   └── screenshots/
│       ├── interoperability_test.png
│       ├── exploit_demo.png
│       └── chat_working.png
│
└── requirements.txt
```

## ⚠️ Important Reminders

1. **DO NOT** include any real vulnerabilities that could harm the host system
2. **DO NOT** include any code that accesses files outside the project directory
3. **DO NOT** submit after the deadline (Oct 26, 2025)
4. **DO** test your submission in a clean environment before submitting
5. **DO** ensure all team members are credited properly

## 🎯 Grading Criteria Coverage

- **Reflective Commentary** (9 pts):
  - [x] Critical reflection on protocol
  - [x] Clear and expressive language
  - [x] Relevance to security concepts
  - [x] Course context connections
  - [x] AI usage discussion
  - [x] Group contributions

- **Implementation** (11 pts):
  - [x] Complete README with examples
  - [x] Testing and interoperability documented
  - [x] Code quality and functionality
  - [x] Feedback given to other groups

- **Backdoors** (6 pts):
  - [x] At least 2 sophisticated vulnerabilities
  - [x] Proof of concept exploits
  - [x] Creative and challenging to find

- **Peer Review** (4 pts):
  - [ ] Review 3 other implementations (individual task)
  - [ ] Provide constructive feedback
  - [ ] Document findings

## 📤 How to Submit

1. **Create ZIP file** with all required files
2. **Name format:** `GroupName_SOCP_Submission.zip`
3. **Upload to MyUni** assignment page before deadline
4. **Verify** submission receipt

## 🚀 Final Steps

1. Replace all placeholder text:
   - `[Your Group Name]`
   - `[Your Names]`
   - `[Member Names]`
   - Update percentages in contributions

2. Test one final time:
   ```bash
   # Clean environment test
   python -m venv test_env
   source test_env/bin/activate  # or test_env\Scripts\activate on Windows
   pip install -r requirements.txt
   python server.py
   python client.py test-user ws://127.0.0.1:9000
   ```

3. Generate screenshots showing:
   - Your chat system working
   - Interoperability with another group
   - Exploit demonstration

4. Review the reflective commentary for:
   - Word count (≤2000 words)
   - All required sections
   - Professional tone
   - No sensitive information

Good luck with your submission! 🎓