"""
PyEncryptor

Programmed by:
Programmed in: Python 3.8.10 (64-Bit)

Description:
This is a Python program used for encrypting a string
into any encryption algorithm you select.
"""

# Used for encrypting the user's string.
import encrypt
# Used for accepting arguments to specify the string to encrypt, and encryption algorithm to use.
import argparse

# Main function for encrypting the user's string.
def main():
    
    # Argument parser for accepting arguments.
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
    
    # Function to write the encrypted string, unencrypted string, and encryption algorithm used into a .txt file
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

    # Function to encrypt the user's string, and display the unencrypted string and the encrypted string.
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

    # Used for showing which encryption algorithms can (currently) be used for encyrpting strings.
    encryption_algorithms = ["MD5", "SHA1", "SHA224", "SHA256","SHA384", "SHA512"]
    encryptor = encrypt.user_string()
    if args.list_algorithms:
        for item in encryption_algorithms:
            print(item)
        print()
    # If the user wants the encrypted, and uncrypted string (recommended) writen into a .txt file. Then with the argument provided, it will encypt the stirng,
    #and have the encrypted string, unencrypted string, and the algorithm used written to the file. And it will show the user on their terminal the encrypted and unecrypted string.
    elif args.write_to_file:
        encrypt_string()
        write_to_file()

    # If the user does not want the encrypted, unencrypted string, and algorithm used into a .txt file. Then after the string had been encrypted, it will display the
    # unencrypted, and encrypted string to the user.
    elif not args.write_to_file:
        encrypt_string()
        
    else:
        pass
 
try:
    main()

except Exception as e:
    print(f"\nError: {e}\n")

