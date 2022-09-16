from classes.CurrentUser import CurrentUser
from classes.CryptoProRegistry import CryptoProRegistry
from modules.AsnDecoder import print_keyfile


def main():
    user = CurrentUser()
    cryptopro = CryptoProRegistry(user.sid)
    print(f"Current user", user)
    print(f"CryptoPro CSP path", cryptopro.keypath)
    print("Container list:")
    for container_name in cryptopro.containers():
        print(container_name)
        container = cryptopro.get_container(container_name)
        print_keyfile(container.key_name)


if __name__ == '__main__':
    main()

