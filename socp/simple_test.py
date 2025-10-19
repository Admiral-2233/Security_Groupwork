#!/usr/bin/env python3
"""
SOCP System Simple Test Script
Test client connection and message passing
"""

import asyncio
import json
import sys
import websockets

async def test_connection(server_url, user_id):
    """Test connection to server"""
    try:
        print(f"🔄 Connecting to {server_url} ...")
        async with websockets.connect(server_url) as ws:
            print(f"✅ Successfully connected to {server_url}")
            
            # Send USER_HELLO message
            hello = {
                "type": "USER_HELLO",
                "from": user_id,
                "to": "server",
                "ts": int(asyncio.get_event_loop().time() * 1000),
                "payload": {
                    "client": "test-v1",
                    "pubkey": "dummy_pubkey_" + user_id
                },
                "sig": ""
            }
            
            await ws.send(json.dumps(hello))
            print(f"📤 Sent HELLO message: {user_id}")
            
            # Wait for response
            response = await asyncio.wait_for(ws.recv(), timeout=5.0)
            print(f"📥 Received response: {response[:100]}...")
            
            return True
            
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

async def main():
    """Main demo function"""
    print("🧪 SOCP System Connection Test")
    print("=" * 40)
    
    # Test two servers
    servers = [
        ("ws://127.0.0.1:9000", "test-alice"),
        ("ws://127.0.0.1:9001", "test-bob")
    ]
    
    results = []
    for url, user_id in servers:
        success = await test_connection(url, user_id)
        results.append((url, success))
        print()
    
    # Print test results
    print("📊 Test Results:")
    for url, success in results:
        status = "✅ Normal" if success else "❌ Failed"
        print(f"  {url}: {status}")
    
    # If all successful, show next steps
    if all(success for _, success in results):
        print("\n🎉 All servers running normally!")
        print("💡 You can now run clients for message passing test:")
        print("   python client.py alice-test ws://127.0.0.1:9000")
        print("   python client.py bob-test ws://127.0.0.1:9001")
    else:
        print("\n⚠️  Some servers have issues, please check logs")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Test ended")