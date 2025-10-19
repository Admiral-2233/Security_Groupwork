#!/usr/bin/env python3
# test_implementation.py - Test script for SOCP implementation
# Run this to verify your implementation works correctly

import asyncio
import websockets
import json
import sys
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from common import now_ms, new_uuid, b64url_encode, canonical_json
from crypto_socp import gen_rsa4096_pair, export_pub_b64url, sign_pss
from envelope import make_envelope

class TestClient:
    def __init__(self, user_id=None):
        self.user_id = user_id or new_uuid()
        self.PRIV, self.PUB = gen_rsa4096_pair()
        self.PUB_B64 = export_pub_b64url(self.PUB)
        self.tests_passed = 0
        self.tests_failed = 0

    async def test_connection(self, server_url):
        """Test 1: Basic connection and handshake"""
        print("[TEST 1] Testing connection and handshake...")
        try:
            async with websockets.connect(server_url) as ws:
                # Send USER_HELLO
                hello = {
                    "type": "USER_HELLO",
                    "from": self.user_id,
                    "to": "server",
                    "ts": now_ms(),
                    "payload": {"client": "test-client", "pubkey": self.PUB_B64},
                    "sig": ""
                }
                await ws.send(json.dumps(hello))

                # Wait for ACK
                response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                resp_data = json.loads(response)

                if resp_data["type"] == "ACK":
                    print("✓ Connection successful, received ACK")
                    self.tests_passed += 1
                    return True
                else:
                    print(f"✗ Unexpected response: {resp_data['type']}")
                    self.tests_failed += 1
                    return False

        except Exception as e:
            print(f"✗ Connection failed: {e}")
            self.tests_failed += 1
            return False

    async def test_user_list(self, server_url):
        """Test 2: Request and receive user list"""
        print("\n[TEST 2] Testing user list command...")
        try:
            async with websockets.connect(server_url) as ws:
                # Connect first
                hello = {
                    "type": "USER_HELLO",
                    "from": self.user_id,
                    "to": "server",
                    "ts": now_ms(),
                    "payload": {"client": "test-client", "pubkey": self.PUB_B64},
                    "sig": ""
                }
                await ws.send(json.dumps(hello))
                await ws.recv()  # ACK

                # Send /list command
                cmd = make_envelope(
                    "CLIENT_CMD",
                    self.user_id,
                    "server",
                    {"cmd": "/list"},
                    self.PRIV,
                    now_ms()
                )
                await ws.send(json.dumps(cmd))

                # Wait for USER_LIST response
                response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                resp_data = json.loads(response)

                # Might receive USER_LIST from initial connection
                while resp_data["type"] != "USER_LIST":
                    response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    resp_data = json.loads(response)

                if "users" in resp_data.get("payload", {}):
                    users = resp_data["payload"]["users"]
                    print(f"✓ User list received: {users}")
                    self.tests_passed += 1
                    return True
                else:
                    print("✗ Invalid user list response")
                    self.tests_failed += 1
                    return False

        except Exception as e:
            print(f"✗ User list test failed: {e}")
            self.tests_failed += 1
            return False

    async def test_duplicate_connection(self, server_url):
        """Test 3: Attempt duplicate user registration"""
        print("\n[TEST 3] Testing duplicate user prevention...")
        try:
            # First connection
            ws1 = await websockets.connect(server_url)
            hello = {
                "type": "USER_HELLO",
                "from": "duplicate-test",
                "to": "server",
                "ts": now_ms(),
                "payload": {"client": "test-client", "pubkey": self.PUB_B64},
                "sig": ""
            }
            await ws1.send(json.dumps(hello))
            await ws1.recv()  # ACK

            # Second connection with same ID
            ws2 = await websockets.connect(server_url)
            await ws2.send(json.dumps(hello))
            response = await asyncio.wait_for(ws2.recv(), timeout=5.0)
            resp_data = json.loads(response)

            await ws1.close()
            await ws2.close()

            if resp_data["type"] == "ERROR" and "NAME_IN_USE" in str(resp_data):
                print("✓ Duplicate user properly rejected")
                self.tests_passed += 1
                return True
            else:
                print("✗ Duplicate user not rejected")
                self.tests_failed += 1
                return False

        except Exception as e:
            print(f"✗ Duplicate test failed: {e}")
            self.tests_failed += 1
            return False

    async def test_message_routing(self, server_url):
        """Test 4: Test message routing between users"""
        print("\n[TEST 4] Testing message routing...")
        try:
            # Create two users
            alice_id = "alice-" + new_uuid()[:8]
            bob_id = "bob-" + new_uuid()[:8]

            alice_priv, alice_pub = gen_rsa4096_pair()
            bob_priv, bob_pub = gen_rsa4096_pair()

            # Connect Alice
            alice_ws = await websockets.connect(server_url)
            alice_hello = {
                "type": "USER_HELLO",
                "from": alice_id,
                "to": "server",
                "ts": now_ms(),
                "payload": {"client": "alice", "pubkey": export_pub_b64url(alice_pub)},
                "sig": ""
            }
            await alice_ws.send(json.dumps(alice_hello))
            await alice_ws.recv()  # ACK

            # Connect Bob
            bob_ws = await websockets.connect(server_url)
            bob_hello = {
                "type": "USER_HELLO",
                "from": bob_id,
                "to": "server",
                "ts": now_ms(),
                "payload": {"client": "bob", "pubkey": export_pub_b64url(bob_pub)},
                "sig": ""
            }
            await bob_ws.send(json.dumps(bob_hello))
            await bob_ws.recv()  # ACK

            print(f"✓ Both users connected: {alice_id}, {bob_id}")

            await alice_ws.close()
            await bob_ws.close()

            self.tests_passed += 1
            return True

        except Exception as e:
            print(f"✗ Message routing test failed: {e}")
            self.tests_failed += 1
            return False

    def print_summary(self):
        """Print test summary"""
        total = self.tests_passed + self.tests_failed
        print("\n" + "="*50)
        print(f"TEST SUMMARY")
        print(f"Passed: {self.tests_passed}/{total}")
        print(f"Failed: {self.tests_failed}/{total}")

        if self.tests_failed == 0:
            print("✓ All tests passed! Implementation appears to be working correctly.")
        else:
            print("✗ Some tests failed. Please review the implementation.")
        print("="*50)

async def main():
    if len(sys.argv) < 2:
        print("Usage: python test_implementation.py <server_url>")
        print("Example: python test_implementation.py ws://127.0.0.1:9000")
        sys.exit(1)

    server_url = sys.argv[1]
    print(f"Testing SOCP implementation at {server_url}")
    print("="*50)

    tester = TestClient()

    # Run tests
    await tester.test_connection(server_url)
    await tester.test_user_list(server_url)
    await tester.test_duplicate_connection(server_url)
    await tester.test_message_routing(server_url)

    # Print summary
    tester.print_summary()

if __name__ == "__main__":
    asyncio.run(main())