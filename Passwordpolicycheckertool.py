import re
import sys
import pyfiglet
import database_handler
import password_history
import password_expiration
import totp_tester
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
        self.users_db = database_handler.UsersDB()
        self.totp_key = self.users_db.get_mfa_key(users_db.lookup_uid(DB_USER))
        totp = totp_tester.TotpProcessor(self.totp_key if self.totp_key else None)
        self.totp_key = totp.get_key()
        self.users_db.insert_mfa_key(users_db.lookup_uid(DB_USER), self.totp_key)
        layout = QVBoxLayout()

        create_banner("Password Policy Checker")

        # Password entry
        self.password_label = QLabel("Enter password to check:")
        self.password_entry = QLineEdit()

        # 2FA entry
        self.totp_label = QLabel("Enter your 2FA code:")
        self.totp_entry = QLineEdit()

        # Validate password
        self.check_button = QPushButton("Check Password")

        # Give password validation results
        self.result_label = QLabel()
        self.strength_label = QLabel()
        self.reuse_label = QLabel()
        self.password_expiry = QLabel()
        self.valid_totp_label = QLabel()
        self.password_updated = QLabel()
        self.last_changed_date = password_expiration.get_last_password_change()

        self.check_button.clicked.connect(self.show_password_policy_result)

        # Add all the widgets to the GUI
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.totp_label)
        layout.addWidget(self.totp_entry)
        layout.addWidget(self.check_button)
        layout.addWidget(self.password_updated)
        layout.addWidget(self.password_expiry)
        layout.addWidget(self.reuse_label)
        layout.addWidget(self.valid_totp_label)
        layout.addWidget(self.result_label)
        layout.addWidget(self.strength_label)

        self.setLayout(layout)

        self.setWindowTitle("Password Policy Checker")
        self.show()

    def show_password_policy_result(self):
        totp = totp_tester.TotpProcessor(self.totp_key)
        password = self.password_entry.text()
        nist_result = check_nist_password_guidelines(password)
        owasp_result = check_owasp_password_guidelines(password)
        password_strength = check_password_strength(password)

        # Interface with database
        uid = self.users_db.lookup_uid(DB_USER)
        hashed = password_history.hash_password(password)
        password_reused = password_history.check_if_password_exists(uid, hashed, PASSWORD_HISTORY)

        # Check if password expired
        if password_expiration.check_password_expiration(self.last_changed_date):
            self.password_expiry.setText("Your password has expired. Please change your password.")

        # Check if password is unique
        if password_reused:
            self.reuse_label.setText(f"Password has been used within the last {PASSWORD_HISTORY} times.")
        else:
            self.reuse_label.setText(f"Password is unique as of the last {PASSWORD_HISTORY} times.")

        # Check if TOTP code is valid
        if totp.validate(self.totp_entry.text()):
            self.valid_totp_label.setText("Entered TOTP Key is correct")
        else:
            self.valid_totp_label.setText("Entered TOTP Key is invalid or has expired")

        # Check if password is complex enough
        if nist_result and owasp_result:
            self.result_label.setText("Password satisfies both NIST and OWASP guidelines.")
        elif nist_result:
            self.result_label.setText("Password satisfies NIST guidelines but not OWASP guidelines.")
        elif owasp_result:
            self.result_label.setText("Password satisfies OWASP guidelines but not NIST guidelines.")
        else:
            self.result_label.setText("Password does not satisfy NIST or OWASP guidelines.")

        # Determine if password should be changed
        if not password_reused and password_strength >= 4 and totp.validate(self.totp_entry.text()):
            if password_history.update_password(uid, hashed):
                self.password_updated.setText("Current password has been updated")
                self.last_changed_date = password_expiration.get_last_password_change()
        else:
            placeholder_text = "Current password was not updated"
            if password_strength < 4:
                placeholder_text += f"\nPassword is not strong enough (minimum of 4 required)"
            self.password_updated.setText(placeholder_text)

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
    users_db = database_handler.UsersDB()
    users_db.insert_new_user(DB_USER, "")
    app = QApplication(sys.argv)
    ex = PasswordPolicyChecker()
    sys.exit(app.exec_())
