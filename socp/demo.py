#!/usr/bin/env python3
"""
Demo script, showcasing the SOCP chat system operation
"""

import asyncio
import subprocess
import time
import sys
import os

def print_section(title):
    print("\n" + "="*50)
    print(f"  {title}")
    print("="*50)

def start_servers():
    """Start server network"""
    print("\n🏗️  Starting server network...")
    
    # Start bootstrap node (port 9000)
    print("🌟 Starting bootstrap node (port 9000)...")
    server1 = subprocess.Popen([
        sys.executable, "server.py", "--port", "9000", "--introducer"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    time.sleep(2)  # Wait for bootstrap node to start
    
    # Start regular node (port 9001)
    print("🔗 Starting regular node (port 9001)...")
    server2 = subprocess.Popen([
        sys.executable, "server.py", "--port", "9001", "--peer", "ws://127.0.0.1:9000"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    time.sleep(3)  # Wait for network to establish
    
    print("✅ Server network started successfully!")
    return server1, server2

def start_clients():
    """Start clients"""
    print("\n👥 Starting clients...")
    
    # Start Alice client
    print("👩 Starting Alice client...")
    alice = subprocess.Popen([
        sys.executable, "client.py", "alice-demo", "ws://127.0.0.1:9000"
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    time.sleep(1)
    
    # Start Bob client
    print("👨 Starting Bob client...")
    bob = subprocess.Popen([
        sys.executable, "client.py", "bob-demo", "ws://127.0.0.1:9001"
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    time.sleep(2)  # Wait for clients to connect
    
    print("✅ Clients started successfully!")
    return alice, bob

def cleanup_processes(processes):
    """Clean up processes"""
    for p in processes:
        try:
            p.terminate()
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()

def demo_interactive():
    """Interactive demo"""
    print("\n🎮 Interactive demo mode")
    print("Press Enter to start demo...")
    input()
    
    # Start servers
    server1, server2 = start_servers()
    
    print("\n⏳ Waiting for network to establish...")
    time.sleep(5)
    
    # Start clients
    alice, bob = start_clients()
    
    print("\n🎬 Demo in progress...")
    print("💡 Tips:")
    print("  • Type /list in client window to view online users")
    print("  • Use /tell username message to send private message")
    print("  • Use /all message to send broadcast message")
    print("  • Use /help to view all commands")
    
    print("\n⏰ Demo will last 60 seconds, press Ctrl+C to end early...")
    
    try:
        time.sleep(60)  # Demo for 60 seconds
    except KeyboardInterrupt:
        print("\n🛑 Demo interrupted")
    
    print("\n🧹 Cleaning up resources...")
    cleanup_processes([alice, bob, server1, server2])
    print("✅ Demo ended!")

def main():
    print("""
╔══════════════════════════════════════════════════════╗
║      SOCP v1.3 - Secure Overlay Chat Protocol Demo   ║
║                                                      ║
║  This demo will showcase:                            ║
║  1. Launching distributed server network             ║
║  2. User registration and authentication            ║
║  3. End-to-end encrypted messaging                    ║
║  4. Public channel communication                     ║
╚══════════════════════════════════════════════════════╝
    """)

    demo_interactive()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Demo ended")