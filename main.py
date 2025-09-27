# main.py

import sys
import socket
from PySide6.QtWidgets import QApplication
from auth import authenticate_user, register_user
from chat import ChatSystem
from gui import ChatWindow


def main():
    # Simple console input to get username and password for demo purposes.
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    # Try to authenticate, if fails and user chooses, register new.
    success, msg = authenticate_user(username, password)
    if not success:
        print(msg)
        choice = input("User not found or wrong password. Register new? (y/n): ")
        if choice.lower() == 'y':
            ok, msg = register_user(username, password)
            if not ok:
                print("Registration failed:", msg)
                sys.exit(1)
            else:
                print("Registration successful, please relaunch to login.")
                sys.exit(0)
        else:
            sys.exit(0)
    # If authentication successful or just registered
    app = QApplication(sys.argv)
    # Choose a default port (could make this configurable or dynamic).
    listen_port = next((port for port in range(9000, 9100)), 9000)
    # Initialize chat system
    chat_system = ChatSystem(username, listen_port)
    # Create and show the main window
    window = ChatWindow(chat_system)
    window.show()
    # Start Qt event loop
    sys.exit(app.exec())


def pick_free_port(start=9000, end=9100):
    for p in range(start, end):
        with socket.socket() as s:
            try:
                s.bind(("", p))
                return p
            except OSError:
                continue
    return 9000

listen_port = pick_free_port()

if __name__ == "__main__":
    main()
