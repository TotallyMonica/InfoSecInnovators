import pyotp
import time
import pyqrcodeng as pyqrcode

class TotpProcessor:
    def __init__(self, key: str=pyotp.random_base32(), username: str=None, issuer: str=None):
        self.totp = None
        self.key = key
        self.username = username
        self.issuer = issuer
        self.generate()

    def generate(self):
        totp = pyotp.totp.TOTP(self.key, issuer=self.issuer, name=self.username)
        totp_uri = totp.provisioning_uri()
        self.totp = totp

        qr = pyqrcode.create(totp_uri, error='L', version=4)
        print(qr.svg("totp.svg"))

    def validate(self, key: str) -> bool:
        return self.totp.verify(key)

    def get_key(self) -> str:
        return self.key