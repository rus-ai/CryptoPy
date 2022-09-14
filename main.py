from classes.CurrentUser import CurrentUser
from classes.CryptoProRegistry import CryptoProRegistry


def main():
    user = CurrentUser()
    cryptopro = CryptoProRegistry(user.sid)
    print(f"Current user", user)
    print(f"CryptoPro CSP path", cryptopro.keypath)
    print("Container list:")
    for container in cryptopro.containers():
        print(container)
        print(cryptopro.get_container(container))


if __name__ == '__main__':
    main()

