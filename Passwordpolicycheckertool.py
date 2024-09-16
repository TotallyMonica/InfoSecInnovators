import re
import sys
import pyfiglet
import password_history
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout
from PyQt5.QtGui import QColor, QPainter

DB_USER = "passwordchecker"
PASSWORD_HISTORY = 3

def create_banner(text):
    ascii_banner = pyfiglet.figlet_format(text)
    print(ascii_banner)

# NIST Password Guidelines
def check_nist_password_guidelines(password):
    nist_len = r'^.{8,}$'  
    nist_complexity = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$'  
    if re.match(nist_len, password) and re.match(nist_complexity, password):
        return True
    else:
        return False

# OWASP Password Guidelines
def check_owasp_password_guidelines(password):
    owasp_len = r'^.{12,}$'  
    owasp_complexity = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]*[^A-Za-z0-9][A-Za-z\d]*$'  
    if re.match(owasp_len, password) and re.match(owasp_complexity, password):
        return True
    else:
        return False

# Password Strength Check
def check_password_strength(password):
    length_strength = min(len(password) // 4, 3)  # Strength increases every 4 characters, capped at 4
    complexity_strength = 0

    if any(char.isupper() for char in password) and any(char.islower() for char in password):
        complexity_strength += 2
    if any(char.isdigit() for char in password):
        complexity_strength += 2
    if any(char in '@$!%*?&' for char in password):
        complexity_strength += 2
    
    total_strength = length_strength + complexity_strength
    return total_strength

class PasswordPolicyChecker(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        create_banner("Password Policy Checker")
        
        self.password_label = QLabel("Enter password to check:")
        self.password_entry = QLineEdit()
        self.check_button = QPushButton("Check Password")
        self.result_label = QLabel()
        self.strength_label = QLabel()
        self.reuse_label = QLabel()

        self.check_button.clicked.connect(self.show_password_policy_result)

        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.check_button)
        layout.addWidget(self.result_label)
        layout.addWidget(self.reuse_label)
        layout.addWidget(self.strength_label)

        self.setLayout(layout)

        self.setWindowTitle("Password Policy Checker")
        self.show()

    def show_password_policy_result(self):
        password = self.password_entry.text()
        nist_result = check_nist_password_guidelines(password)
        owasp_result = check_owasp_password_guidelines(password)
        password_strength = check_password_strength(password)

        # Interface with database
        uid = password_history.lookup_uid(DB_USER)
        hashed = password_history.hash_password(password)
        password_reused = password_history.check_if_password_exists(uid, hashed, PASSWORD_HISTORY)

        if password_reused:
            self.reuse_label.setText(f"Password has been used within the last {PASSWORD_HISTORY} times.")
        else:
            self.reuse_label.setText(f"Password is unique as of the last {PASSWORD_HISTORY} times.")

        if nist_result and owasp_result:
            self.result_label.setText("Password satisfies both NIST and OWASP guidelines.")
        elif nist_result:
            self.result_label.setText("Password satisfies NIST guidelines but not OWASP guidelines.")
        elif owasp_result:
            self.result_label.setText("Password satisfies OWASP guidelines but not NIST guidelines.")
        else:
            self.result_label.setText("Password does not satisfy NIST or OWASP guidelines.")

        if not password_reused and password_strength >= 4:
            self.reuse_label.setText("Current password has been updated")
            password_history.update_password(uid, hashed)

        self.strength_label.setText(f"Password Strength: {password_strength}")

        # Visualize password strength with colored bars
        self.strength_label.setStyleSheet(f"background-color: {self.get_color(password_strength)}")

    def get_color(self, strength):
        if strength >=0 and strength <=1:
            return "red"
        elif strength >=2 and strength <=3:
            return "orange"
        elif strength >=4 and strength <=5:
            return "yellow"
        elif strength > 5:
            return "green"

if __name__ == '__main__':
    password_history.insert_new_user(DB_USER, "")
    app = QApplication(sys.argv)
    ex = PasswordPolicyChecker()
    sys.exit(app.exec_())
