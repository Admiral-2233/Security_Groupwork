#!/usr/bin/env python3
"""
SOCP System Simplified Demo Script
Avoid complex connection errors
"""

import asyncio
import json
import sys
import websockets
import threading
import time

class SimpleClient:
    def __init__(self, user_id, server_url):
        self.user_id = user_id
        self.server_url = server_url
        self.ws = None
        self.running = True
    
    async def connect(self):
        """Connect to server"""
        try:
            print(f"🔄 {self.user_id} connecting to {self.server_url}...")
            self.ws = await websockets.connect(self.server_url)
            
            # 发送USER_HELLO
            hello = {
                "type": "USER_HELLO",
                "from": self.user_id,
                "to": "server",
                "ts": int(time.time() * 1000),
                "payload": {
                    "client": "demo-v1",
                    "pubkey": f"demo_pubkey_{self.user_id}"
                },
                "sig": ""
            }
            
            await self.ws.send(json.dumps(hello))
            print(f"✅ {self.user_id} connected successfully!")
            return True
            
        except Exception as e:
            print(f"❌ {self.user_id} connection failed: {e}")
            return False
    
    async def listen(self):
        """Listen for messages"""
        try:
            while self.running:
                message = await self.ws.recv()
                data = json.loads(message)
                
                if data.get("type") == "USER_LIST":
                    users = data.get("payload", {}).get("users", [])
                    print(f"👥 {self.user_id} online users: {users}")
                elif data.get("type") == "USER_MESSAGE":
                    from_user = data.get("from", "unknown")
                    text = data.get("payload", {}).get("text", "")
                    print(f"💬 {self.user_id} received message from {from_user}: {text}")
                elif data.get("type") == "ACK":
                    print(f"📤 {self.user_id} message delivered")
                
        except websockets.exceptions.ConnectionClosed:
            print(f"🔌 {self.user_id} connection closed")
        except Exception as e:
            print(f"⚠️ {self.user_id} listen error: {e}")
    
    async def send_message(self, to_user, text):
        """Send message"""
        try:
            msg = {
                "type": "USER_MESSAGE",
                "from": self.user_id,
                "to": to_user,
                "ts": int(time.time() * 1000),
                "payload": {"text": text},
                "sig": ""
            }
            await self.ws.send(json.dumps(msg))
            print(f"📤 {self.user_id} -> {to_user}: {text}")
        except Exception as e:
            print(f"⚠️ {self.user_id} failed to send message: {e}")
    
    async def request_user_list(self):
        """Request user list"""
        try:
            msg = {
                "type": "USER_LIST",
                "from": self.user_id,
                "to": "server",
                "ts": int(time.time() * 1000),
                "payload": {},
                "sig": ""
            }
            await self.ws.send(json.dumps(msg))
        except Exception as e:
            print(f"⚠️ {self.user_id} failed to request user list: {e}")
    
    async def close(self):
        """Close connection"""
        self.running = False
        if self.ws:
            await self.ws.close()
            print(f"👋 {self.user_id} disconnected")

async def demo_alice():
    """Alice demo"""
    alice = SimpleClient("alice-demo", "ws://127.0.0.1:9000")
    
    if await alice.connect():
        # Start listening task
        listen_task = asyncio.create_task(alice.listen())
        
        # Wait for connection to stabilize
        await asyncio.sleep(2)
        
        # Request user list
        await alice.request_user_list()
        await asyncio.sleep(1)
        
        # Send message to Bob
        await alice.send_message("bob-demo", "Hello Bob! 👋")
        await asyncio.sleep(2)
        
        # Send public message
        await alice.send_message("all", "Hello everyone! 🌍")
        
        # Run for a while
        await asyncio.sleep(5)
        
        # Cleanup
        listen_task.cancel()
        await alice.close()

async def demo_bob():
    """Bob demo"""
    bob = SimpleClient("bob-demo", "ws://127.0.0.1:9000")
    
    if await bob.connect():
        # Start listening task
        listen_task = asyncio.create_task(bob.listen())
        
        # Wait for connection to stabilize
        await asyncio.sleep(2)
        
        # Request user list
        await bob.request_user_list()
        await asyncio.sleep(1)
        
        # Send message to Alice
        await bob.send_message("alice-demo", "Hi Alice! 😊")
        await asyncio.sleep(2)
        
        # Send public message
        await bob.send_message("all", "Hey all! 🎉")
        
        # Run for a while
        await asyncio.sleep(5)
        
        # Cleanup
        listen_task.cancel()
        await bob.close()

async def main():
    """Main demo function"""
    print("🎭 SOCP System Simplified Demo")
    print("=" * 40)
    
    # Run Alice and Bob in parallel
    await asyncio.gather(demo_alice(), demo_bob())
    
    print("\n🎉 Demo completed!")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demo ended")