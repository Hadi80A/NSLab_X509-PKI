import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, QInputDialog, QFileDialog, \
    QTableWidget, QTableWidgetItem
from PyQt5.QtGui import QFont
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from client import Client
from cert_info import certificate_info


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.client = Client('ca.crt')

        self.setWindowTitle("Certificate Management")
        self.setGeometry(100, 100, 600, 400)

        # Central widget setup
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Layout for central widget
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        # Create main menu
        self.create_main_menu()

    def create_main_menu(self):
        # Clear layout
        while self.layout.count():
            child = self.layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        # Request Cert Button
        self.request_cert_button = QPushButton("Request Cert", self)
        self.request_cert_button.setFont(QFont("Arial", 14))
        self.request_cert_button.setStyleSheet(
            "QPushButton {"
            "background-color: #4CAF50;"
            "border: none;"
            "color: white;"
            "padding: 15px 32px;"
            "text-align: center;"
            "text-decoration: none;"
            "font-size: 16px;"
            "}"
            "QPushButton:hover {background-color: #45a049;}"
            "QPushButton:pressed {background-color: #367c39;}"
        )
        self.request_cert_button.clicked.connect(self.request_cert)
        self.layout.addWidget(self.request_cert_button)

        # View Cert Info Button
        self.view_cert_button = QPushButton("View Cert Info", self)
        self.view_cert_button.setFont(QFont("Arial", 14))
        self.view_cert_button.setStyleSheet(
            "QPushButton {"
            "background-color: #008CBA;"
            "border: none;"
            "color: white;"
            "padding: 15px 32px;"
            "text-align: center;"
            "text-decoration: none;"
            "font-size: 16px;"
            "}"
            "QPushButton:hover {background-color: #007B9F;}"
            "QPushButton:pressed {background-color: #005F79;}"
        )
        self.view_cert_button.clicked.connect(self.view_cert_info)
        self.layout.addWidget(self.view_cert_button)

        # Verify Button
        self.verify_button = QPushButton("Verify", self)
        self.verify_button.setFont(QFont("Arial", 14))
        self.verify_button.setStyleSheet(
            "QPushButton {"
            "background-color: #FFA500;"
            "border: none;"
            "color: white;"
            "padding: 15px 32px;"
            "text-align: center;"
            "text-decoration: none;"
            "font-size: 16px;"
            "}"
            "QPushButton:hover {background-color: #FF8C00;}"
            "QPushButton:pressed {background-color: #FF4500;}"
        )
        self.verify_button.clicked.connect(self.verify_cert)
        self.layout.addWidget(self.verify_button)

    def verify_cert(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Certificate File", "",
                                                   "Certificate Files (*.crt)")
        if file_name:
            print("File selected:", file_name)
            with open(file_name, 'rb') as cert_file:
                cert_data = cert_file.read()
                # cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            self.client.verify_cert(cert_data)
    def request_cert(self):
        name, ok_pressed = QInputDialog.getText(self, "Certificate Request", "Enter your name:")
        if ok_pressed:
            self.client.set_name(name)
            self.client.send_cert_request()

    def view_cert_info(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Certificate File", "",
                                                   "Certificate Files (*.crt)")
        if file_name:
            print("File selected:", file_name)
            info = certificate_info(file_name)
            self.show_cert_info_table(info)

    def show_cert_info_table(self,data):
        # Clear layout
        while self.layout.count():
            child = self.layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        table_widget = QTableWidget()
        table_widget.setColumnCount(2)
        table_widget.setRowCount(len(data))  # You can set the number of rows as needed

        # Setting headers
        table_widget.setHorizontalHeaderLabels(["Attribute", "Value"])
        for row, d in enumerate(data.items()):
            for col, item in enumerate(d):
                table_widget.setItem(row, col, QTableWidgetItem(str(item)))


        # Show the table
        table_widget.resizeColumnsToContents()
        self.layout.addWidget(table_widget)

        # Add back button
        back_button = QPushButton("Back", self)
        back_button.setFont(QFont("Arial", 14))
        back_button.setStyleSheet(
            "QPushButton {"
            "background-color: #f44336;"
            "border: none;"
            "color: white;"
            "padding: 15px 32px;"
            "text-align: center;"
            "text-decoration: none;"
            "font-size: 16px;"
            "}"
            "QPushButton:hover {background-color: #d32f2f;}"
            "QPushButton:pressed {background-color: #b71c1c;}"
        )
        back_button.clicked.connect(self.create_main_menu)
        self.layout.addWidget(back_button)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
