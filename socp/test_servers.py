#!/usr/bin/env python3
"""Quick test to verify servers are running"""

import asyncio
import websockets
import json
from common import now_ms, new_uuid

async def test_server(port):
    """Test if server is responding"""
    try:
        uri = f"ws://127.0.0.1:{port}"
        async with websockets.connect(uri) as ws:
            # Send a simple USER_HELLO
            hello = {
                "type": "USER_HELLO",
                "from": f"test-{port}",
                "to": "server",
                "ts": now_ms(),
                "payload": {"client": "test"},
                "sig": ""
            }
            await ws.send(json.dumps(hello))

            # Wait for response
            response = await asyncio.wait_for(ws.recv(), timeout=2.0)
            resp_data = json.loads(response)

            if resp_data.get("type"):
                print(f"✅ Server on port {port} is running")
                return True
    except Exception as e:
        print(f"❌ Server on port {port} is not responding: {e}")
        return False

async def main():
    print("Testing SOCP Servers...")
    print("-" * 40)

    # Test both servers
    results = await asyncio.gather(
        test_server(9000),
        test_server(9001)
    )

    if all(results):
        print("\n✅ All servers are running properly!")
    else:
        print("\n⚠️ Some servers are not running. Please check.")

if __name__ == "__main__":
    asyncio.run(main())