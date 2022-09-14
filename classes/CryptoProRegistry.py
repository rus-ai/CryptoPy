from winreg import ConnectRegistry, OpenKey
from winreg import HKEY_LOCAL_MACHINE


CRYPTO_PRO_64 = 'SOFTWARE\\WOW6432Node\\Crypto Pro\\'
CRYPTO_PRO_32 = 'SOFTWARE\\Crypto Pro\\'


class CryptoProRegistry:
    def __init__(self, sid):
        self.keypath = f'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Crypto Pro\\Settings\\Users\\{sid}\\Keys'
        reg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        try:
            _ = OpenKey(reg, f'{CRYPTO_PRO_64}')
            self.keypath = f'{CRYPTO_PRO_64}Settings\\Users\\{sid}\\Keys\\'
        except:
            try:
                _ = OpenKey(reg, f'{CRYPTO_PRO_32}')
                self.keypath = f'{CRYPTO_PRO_32}Settings\\Users\\{sid}\\Keys\\'
            except:
                raise Exception('CryptoPro not installed')

