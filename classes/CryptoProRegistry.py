from winreg import ConnectRegistry, OpenKey, EnumKey, QueryValueEx
from winreg import HKEY_LOCAL_MACHINE

from classes.CryptoContainer import CryptoContainer

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

    def containers(self):
        reg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        key = OpenKey(reg, self.keypath)
        counter = 0
        while True:
            try:
                subkey = EnumKey(key, counter)
                counter += 1
                yield subkey
            except WindowsError as e:
                break

    def get_container(self, name):
        reg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        key = OpenKey(reg, f"{self.keypath}{name}")
        container = CryptoContainer(name, "registry")
        container.key_header, _ = QueryValueEx(key, "header.key")
        container.key_masks, _ = QueryValueEx(key, "masks.key")
        container.key_masks2, _ = QueryValueEx(key, "masks2.key")
        container.key_name, _ = QueryValueEx(key, "name.key")
        container.key_primary, _ = QueryValueEx(key, "primary.key")
        container.key_primary2, _ = QueryValueEx(key, "primary2.key")
        return container
