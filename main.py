from classes.CurrentUser import CurrentUser
from classes.CryptoProRegistry import CryptoProRegistry


def main():
    user = CurrentUser()
    cryptopro = CryptoProRegistry(user.sid)
    print(f"Current user", user)
    print(f"CryptoPro CSP path", cryptopro.keypath)
    pass


if __name__ == '__main__':
    main()

