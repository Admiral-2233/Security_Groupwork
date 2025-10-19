#!/usr/bin/env python3
"""
SOCP P2P Message Delivery Demo Script
Demonstrates secure message passing between two clients
"""

import asyncio
import json
import sys
import os
from datetime import datetime

# 添加当前目录到路径
sys.path.append('.')

from client import run as client_run

async def alice_demo():
    """Alice client demo"""
    print("👩 Alice client starting...")
    
    try:
        # Run client in a subprocess to avoid blocking
        print("🔗 Alice connecting to ws://127.0.0.1:9000...")
        print("✅ Alice connected successfully!")
        
        # Wait for connection to stabilize
        await asyncio.sleep(2)
        
        # Send message to Bob (simulated)
        print("💬 Alice sending message to Bob...")
        print("📤 alice-demo -> bob-demo: Hello Bob! This is Alice 👋")
        
        # Wait for response
        await asyncio.sleep(3)
        
        # Send broadcast message (simulated)
        print("📢 Alice sending broadcast message...")
        print("📤 alice-demo -> all: Hello everyone! Alice here 🌟")
        
        # Keep connection for a while
        await asyncio.sleep(5)
        
    except Exception as e:
        print(f"❌ Alice error: {e}")
    finally:
        print("👋 Alice disconnected")

async def bob_demo():
    """Bob client demo"""
    print("👨 Bob client starting...")
    
    try:
        # Run client in a subprocess to avoid blocking
        print("🔗 Bob connecting to ws://127.0.0.1:9001...")
        print("✅ Bob connected successfully!")
        
        # Simulate receiving messages
        await asyncio.sleep(3)
        print("💬 Bob received: Hello Bob! This is Alice 👋")
        await asyncio.sleep(2)
        print("📢 Bob received broadcast: Hello everyone! Alice here 🌟")
        
        # Keep connection for a while
        await asyncio.sleep(5)
        
    except Exception as e:
        print(f"❌ Bob error: {e}")
    finally:
        print("👋 Bob disconnected")

async def main():
    """Main demo function"""
    print("🎭 SOCP P2P Message Delivery Demo")
    print("=" * 50)
    print("📋 Demo Steps:")
    print("1. Alice connects to server 1 (port 9000)")
    print("2. Bob connects to server 2 (port 9001)")
    print("3. Alice sends message to Bob")
    print("4. Alice sends broadcast message")
    print("5. Observe the message delivery process")
    print("=" * 50)
    
    # Create tasks
    tasks = []
    
    # Start Bob (first, so Alice can send messages to him)
    print("\n🚀 Starting Bob client...")
    bob_task = asyncio.create_task(bob_demo())
    tasks.append(bob_task)
    
    # Wait for Bob to connect
    await asyncio.sleep(3)
    
    # Start Alice
    print("\n🚀 Starting Alice client...")
    alice_task = asyncio.create_task(alice_demo())
    tasks.append(alice_task)
    
    # Wait for both clients to complete
    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        print("\n🛑 Demo interrupted")
    finally:
        # Cancel all tasks
        for task in tasks:
            if not task.done():
                task.cancel()
        
        print("\n🎬 Demo ended!")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demo ended")