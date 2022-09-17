from classes.Asn1Object import Asn1Object
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
        if container_name == "Samara2021":
            container = cryptopro.get_container(container_name)
            print_keyfile(container.key_header)
            asn1 = Asn1Object(container.key_header)
            print(asn1)


if __name__ == '__main__':
    main()

