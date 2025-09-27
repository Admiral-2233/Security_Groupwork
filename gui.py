# gui.py
#
# Defines the graphical user interface for the chat application.
from PySide6.QtWidgets import QApplication, QMainWindow, QListWidget, QTextEdit, QLineEdit, QPushButton, QWidget, \
    QHBoxLayout, QVBoxLayout, QFileDialog, QLabel


class ChatWindow(QMainWindow):
    def __init__(self, chat_system):
        super().__init__()
        self.chat = chat_system  # ChatSystem instance
        self.setWindowTitle("Secure P2P Chat")
        self.resize(800, 600)
        # Main container widget
        central = QWidget()
        self.setCentralWidget(central)
        # Layouts
        main_layout = QHBoxLayout(central)
        left_layout = QVBoxLayout()
        right_layout = QVBoxLayout()
        main_layout.addLayout(left_layout, 1)  # user list panel
        main_layout.addLayout(right_layout, 3)  # chat panel (bigger)
        # Left side (users list)
        self.user_list = QListWidget()
        left_layout.addWidget(QLabel("Online Users:"))
        left_layout.addWidget(self.user_list)
        # Right side (chat display and input)
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.message_input = QLineEdit()
        send_btn = QPushButton("Send")
        file_btn = QPushButton("Send File")
        # Layout for input and buttons
        input_layout = QHBoxLayout()
        input_layout.addWidget(self.message_input)
        input_layout.addWidget(send_btn)
        input_layout.addWidget(file_btn)
        right_layout.addWidget(QLabel("Chat:"))
        right_layout.addWidget(self.chat_display)
        right_layout.addLayout(input_layout)
        # Connect signals
        send_btn.clicked.connect(self._send_message)
        file_btn.clicked.connect(self._send_file)
        # Connect chat_system signals to update UI
        self.chat.user_joined.connect(self._on_user_joined)
        self.chat.message_received.connect(self._on_message_received)
        self.chat.file_received.connect(self._on_file_received)
        # Populate initial user list (in case some peers already connected)
        for name in self.chat.network.connections.keys():
            if name != "UnknownPeer":
                self.user_list.addItem(name)

        self.user_list.addItem(self.chat.local_username + " (me)")

    def _on_user_joined(self, username):
        self.user_list.addItem(username)
        self.chat_display.append(f"* {username} joined the chat *")

    def _on_message_received(self, from_user, message):
        # Append message to chat display
        self.chat_display.append(f"{from_user}: {message}")

    def _on_file_received(self, from_user, file_bytes, filename):
        # Save the file bytes to disk or open a save dialog
        save_path, _ = QFileDialog.getSaveFileName(self, f"Save file from {from_user}", filename)
        if save_path:
            try:
                with open(save_path, "wb") as f:
                    f.write(file_bytes)
                self.chat_display.append(f"* File '{filename}' received from {from_user} (saved to {save_path}) *")
            except Exception as e:
                self.chat_display.append(f"* Failed to save file from {from_user}: {e} *")

    def _send_message(self):
        text = self.message_input.text().strip()
        if not text:
            return
        # Determine target: if a user is selected in list, send private, else broadcast
        target = "ALL"
        current_item = self.user_list.currentItem()
        if current_item:
            target = current_item.text()
        self.chat.send_message(target, text)
        # Also echo the message to own display
        if target == "ALL":
            self.chat_display.append(f"{self.chat.local_username} (to All): {text}")
        else:
            self.chat_display.append(f"{self.chat.local_username} (to {target}): {text}")
        self.message_input.clear()

    def _send_file(self):
        # Open file dialog to choose a file
        file_path, _ = QFileDialog.getOpenFileName(self, "Select file to send")
        if not file_path:
            return
        target = "ALL"
        current_item = self.user_list.currentItem()
        if current_item:
            target = current_item.text()
        success, msg = self.chat.send_file(target, file_path)
        if success:
            self.chat_display.append(
                f"* Sent file '{os.path.basename(file_path)}' to {('All' if target == 'ALL' else target)} *")
        else:
            self.chat_display.append(f"* Failed to send file: {msg} *")
