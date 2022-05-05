"""
PyEncryptor

Programmed by:
Programmed in: Python 3.8.10 (64-Bit)

Description:
This is a Python program used for encrypting a string
into any encryption algorithm you select.
"""
import encrypt
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.description = """Securly encrypt your strings with (almost) any encryption algorithm.
    """
    parser.add_argument("--string","--string", help="String to encrypt.")
    parser.add_argument("--algorithm", "--algorithm", help="Encryption algorithm to use to encrypt the string.")
    parser.add_argument("--list-algorithms", "--list_algorithms", help="List all encryption algorithms to encrypt your string.", action="store_true")
    parser.add_argument("--write-to-file", "--write_to_file", help="If present, it will store the string and encrypted string into a txt file. [RECOMMENDED]", action="store_true")
    args = parser.parse_args()
    algorithm = str(args.algorithm)
    string = str(args.string)

    if algorithm == "" or string == "":
        if algorithm == "" or algorithm == None:
            print("\nPlease enter an encryption algorithm\n")

        elif string == "" or string == None:
            print("\nPlease enter a string to encrypt\n")

    else:
        pass

    def write_to_file():
        file_stream = open("Encrypted.txt", "w")

        if algorithm.upper() == "MD5":
            hashed_string = encryptor.md5(string)
            file_stream.write(
f"""
String: {string}
Hash Algorithm: {algorithm.upper()}
Hashed value: {hashed_string}

""")

        elif algorithm.upper() == "SHA1":
            hashed_string = encryptor.sha1(string)
            file_stream.write(
f"""
String: {string}
Hash Algorithm: {algorithm.upper()}
Hashed value: {hashed_string}

""")

        elif algorithm.upper() == "SHA224":
            hashed_string = encryptor.sha224(string)
            file_stream.write(
f"""
String: {string}
Hash Algorithm: {algorithm.upper()}
Hashed value: {hashed_string}

""")

        elif algorithm.upper() == "SHA256":
            hashed_string = encryptor.sha256(string)
            file_stream.write(
f"""
String: {string}
Hash Algorithm: {algorithm.upper()}
Hashed value: {hashed_string}

""")

        elif algorithm.upper() == "SHA384":
            hashed_string = encryptor.sha384(string)
            file_stream.write(
f"""
String: {string}
Hash Algorithm: {algorithm.upper()}
Hashed value: {hashed_string}

""")

        elif algorithm.upper() == "SHA512":
            hashed_string = encryptor.sha512(string)
            file_stream.write(
f"""
String: {string}
Hash Algorithm: {algorithm.upper()}
Hashed value: {hashed_string}

""")

        else:
            pass


    def encrypt_string():

        if algorithm.upper() == "MD5":
            hashed_string = encryptor.md5(string)
            print(f"\nString: {string}\nHashed value: {hashed_string}\n")

        elif algorithm.upper() == "SHA1":
            hashed_string = encryptor.sha1(string)
            print(f"\nString: {string}\nHashed value: {hashed_string}\n")

        elif algorithm.upper() == "SHA224":
            hashed_string = encryptor.sha224(string)
            print(f"\nString: {string}\nHashed value: {hashed_string}\n")

        elif algorithm.upper() == "SHA256":
            hashed_string = encryptor.sha256(string)
            print(f"\nString: {string}\nHashed value: {hashed_string}\n")

        elif algorithm.upper() == "SHA384":
            hashed_string = encryptor.sha384(string)
            print(f"\nString: {string}\nHashed value: {hashed_string}\n")

        elif algorithm.upper() == "SHA512":
            hashed_string = encryptor.sha512(string)
            print(f"\nString: {string}\nHashed value: {hashed_string}\n")

        else:
            pass


    encryption_algorithms = ["MD5", "SHA1", "SHA224", "SHA256","SHA384", "SHA512"]
    encryptor = encrypt.user_string()
    if args.list_algorithms:
        for item in encryption_algorithms:
            print(item)
        print()

    elif args.write_to_file:
        encrypt_string()
        write_to_file()


    elif not args.write_to_file:
        encrypt_string()
        
    else:
        pass
 
try:
    main()

except Exception as e:
    raise e

