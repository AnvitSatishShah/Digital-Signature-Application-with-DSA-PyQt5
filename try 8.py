import sys
import os
import hashlib
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QStackedWidget, \
    QHBoxLayout, QTabWidget
from PyQt5.QtGui import QDragEnterEvent, QDropEvent, QPalette, QColor, QFont
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization


def compute_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as file:
        hasher.update(file.read())
    return hasher.hexdigest()


class ThemeToggle(QPushButton):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(30, 30)
        self.setCursor(Qt.PointingHandCursor)
        self.setCheckable(True)
        self.clicked.connect(self.toggle_theme)
        self.update_icon()

    def update_icon(self):
        self.setText("🌞" if self.isChecked() else "🌙")

    def toggle_theme(self):
        self.update_icon()
        app = QApplication.instance()
        if self.isChecked():
            # Light theme
            palette = QPalette()
            palette.setColor(QPalette.Window, QColor(240, 240, 240))
            palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
            palette.setColor(QPalette.Base, QColor(255, 255, 255))
            palette.setColor(QPalette.Text, QColor(0, 0, 0))
            palette.setColor(QPalette.Button, QColor(240, 240, 240))
            palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))
        else:
            # Dark theme
            palette = QPalette()
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
            palette.setColor(QPalette.Base, QColor(35, 35, 35))
            palette.setColor(QPalette.Text, QColor(255, 255, 255))
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        app.setPalette(palette)


class UploadWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        self.setAcceptDrops(True)

        self.label = QLabel("Drag & Drop a file here or click 'Browse' to select")
        layout.addWidget(self.label)

        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.select_file)
        layout.addWidget(self.browse_button)

        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.go_back)
        layout.addWidget(self.back_button)

        self.setLayout(layout)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            self.main_window.file_path = url.toLocalFile()
            self.main_window.update_file_label()
        self.main_window.stacked_widget.setCurrentIndex(0)

    def select_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "",
                                                   "Images & PDFs (*.jpeg *.jpg *.png *.pdf)", options=options)
        if file_path:
            self.main_window.file_path = file_path
            self.main_window.update_file_label()
        self.main_window.stacked_widget.setCurrentIndex(0)

    def go_back(self):
        self.main_window.stacked_widget.setCurrentIndex(0)


class AdvancedWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.initUI()

    def initUI(self):
        # Create main layout
        layout = QVBoxLayout()

        # Create tab widget
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Sanserif", 12))

        # Create individual tabs
        self.security_tab = QWidget()
        self.file_management_tab = QWidget()
        self.additional_features_tab = QWidget()

        # Add tabs to widget
        self.tabs.addTab(self.security_tab, "Security Settings")
        self.tabs.addTab(self.file_management_tab, "File Management")
        self.tabs.addTab(self.additional_features_tab, "Additional Features")

        # Initialize tab layouts
        self.init_security_tab()
        self.init_file_management_tab()
        self.init_additional_features_tab()

        # Add back button
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.go_back)

        # Add widgets to main layout
        layout.addWidget(self.tabs)
        layout.addWidget(self.back_button)
        self.setLayout(layout)

    def init_security_tab(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Security Settings Coming Soon"))
        self.security_tab.setLayout(layout)

    def init_file_management_tab(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("File Management Coming Soon"))
        self.file_management_tab.setLayout(layout)

    def init_additional_features_tab(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Additional Features Coming Soon"))
        self.additional_features_tab.setLayout(layout)

    def go_back(self):
        self.main_window.stacked_widget.setCurrentIndex(0)


class DigitalSignatureApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.stacked_widget = QStackedWidget()

        self.main_window = QWidget()
        self.upload_window = UploadWindow(self)

        self.init_main_window()

        self.stacked_widget.addWidget(self.main_window)
        self.stacked_widget.addWidget(self.upload_window)

        # Add Advanced window to stacked widget
        self.advanced_window = AdvancedWindow(self)
        self.stacked_widget.addWidget(self.advanced_window)

        # Main layout for the entire app
        layout = QVBoxLayout()

        # Header layout for theme toggle
        header = QHBoxLayout()
        header.addStretch()
        self.theme_toggle = ThemeToggle()
        header.addWidget(self.theme_toggle)

        # Add layouts to main layout
        layout.addLayout(header)
        layout.addWidget(self.stacked_widget)

        self.setLayout(layout)
        self.setWindowTitle("Digital Signature App")
        self.file_path = None

    def init_main_window(self):
        layout = QVBoxLayout()

        self.label = QLabel("Select a file to sign or verify:")
        layout.addWidget(self.label)

        self.supported_types_label = QLabel("Supported file types: JPEG, PNG, PDF")
        layout.addWidget(self.supported_types_label)

        self.file_display_layout = QVBoxLayout()
        file_info_layout = QHBoxLayout()
        self.file_name_label = QLabel("")
        self.remove_file_button = QPushButton("X")
        self.remove_file_button.setFixedSize(20, 20)
        self.remove_file_button.clicked.connect(self.remove_file)
        file_info_layout.addWidget(self.file_name_label)
        file_info_layout.addWidget(self.remove_file_button)
        file_info_layout.addStretch()
        self.file_display_layout.addLayout(file_info_layout)

        self.file_hash_label = QLabel("")
        self.file_display_layout.addWidget(self.file_hash_label)
        layout.addLayout(self.file_display_layout)

        self.file_name_label.hide()
        self.remove_file_button.hide()
        self.file_hash_label.hide()

        self.upload_button = QPushButton("Upload")
        self.upload_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        layout.addWidget(self.upload_button)

        self.sign_button = QPushButton("Sign File")
        self.sign_button.clicked.connect(self.sign_file)
        layout.addWidget(self.sign_button)

        self.verify_button = QPushButton("Verify Signature")
        self.verify_button.clicked.connect(self.verify_signature)
        layout.addWidget(self.verify_button)

        self.result_label = QLabel("")
        layout.addWidget(self.result_label)

        # Add Advanced button
        advanced_button = QPushButton("Advanced")
        advanced_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
        
        # Create button layout for bottom row
        button_layout = QHBoxLayout()
        button_layout.addStretch()  # Push button to right
        button_layout.addWidget(advanced_button)
        
        layout.addLayout(button_layout)
        
        self.main_window.setLayout(layout)

    def update_file_label(self):
        if self.file_path:
            self.file_name_label.setText(os.path.basename(self.file_path))
            self.file_name_label.show()
            self.remove_file_button.show()
            file_hash = compute_file_hash(self.file_path)
            self.file_hash_label.setText(f"SHA-256: {file_hash}")
            self.file_hash_label.show()
        else:
            self.file_name_label.hide()
            self.remove_file_button.hide()
            self.file_hash_label.hide()

    def remove_file(self):
        self.file_path = None
        self.update_file_label()

    def sign_file(self):
        if not self.file_path:
            self.result_label.setText("No file selected.")
            return

        if os.path.exists("private_key.pem"):
            with open("private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password=None)
        else:
            private_key = dsa.generate_private_key(key_size=1024)

        public_key = private_key.public_key()

        with open(self.file_path, "rb") as file:
            data = file.read()
            signature = private_key.sign(data, hashes.SHA256())

        file_hash = compute_file_hash(self.file_path)
        sig_path = file_hash + ".sig"
        with open(sig_path, "wb") as sig_file:
            sig_file.write(signature)

        with open("public_key.pem", "wb") as key_file:
            key_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))

        with open("private_key.pem", "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        self.result_label.setText("File signed successfully!")

    def verify_signature(self):
        if not self.file_path:
            self.result_label.setText("No file selected.")
            return

        file_hash = compute_file_hash(self.file_path)
        sig_path = file_hash + ".sig"
        if not os.path.exists(sig_path):
            self.result_label.setText("Signature file not found!")
            return

        if not os.path.exists("public_key.pem"):
            self.result_label.setText("Public key file not found!")
            return

        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        with open(self.file_path, "rb") as file:
            data = file.read()

        with open(sig_path, "rb") as sig_file:
            signature = sig_file.read()

        try:
            public_key.verify(signature, data, hashes.SHA256())
            self.result_label.setText("Signature verified successfully!")
        except:
            self.result_label.setText("Signature verification failed!")


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Set default (light) theme
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(240, 240, 240))
    palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
    palette.setColor(QPalette.Base, QColor(255, 255, 255))
    palette.setColor(QPalette.Text, QColor(0, 0, 0))
    palette.setColor(QPalette.Button, QColor(240, 240, 240))
    palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))
    app.setPalette(palette)

    window = DigitalSignatureApp()
    window.show()
    sys.exit(app.exec_())