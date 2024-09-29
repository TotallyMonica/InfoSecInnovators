import pyotp
import pyqrcodeng as pyqrcode

class TotpProcessor:
    def __init__(self, key: str=pyotp.random_base32(), username: str=None, issuer: str=None):
        self.totp = None
        if key is None:
            self.key = pyotp.random_base32()
        else:
            self.key = key
        self.username = username
        self.issuer = issuer
        self.generate()

    def generate(self, file_type: str='png'):
        totp = pyotp.totp.TOTP(self.key, issuer=self.issuer, name=self.username)
        totp_uri = totp.provisioning_uri()
        self.totp = totp

        qr = pyqrcode.create(totp_uri, error='L', version=4)
        if file_type.lower() == 'png':
            qr.png("totp.png")
        elif file_type.lower() == 'cli' or file_type.lower().startswith('term'):
            qr.term()
        elif file_type.lower() == 'svg':
            qr.svg("totp.svg")

    def validate(self, key: str) -> bool:
        return self.totp.verify(key)

    def get_key(self) -> str:
        return self.key