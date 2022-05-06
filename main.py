"""
PyEncryptor

Programmed by:
Programmed in: Python 3.8.10 (64-Bit)

Description:
This is a Python program used for encrypting a string
into any encryption algorithm you select.
"""


def main():
    import encrypt
    import argparse
    import os


    parser = argparse.ArgumentParser()
    parser.description = """Securly encrypt your strings with (almost) any encryption algorithm.
    """
    parser.add_argument("--string","--string", help="String to encrypt.")
    parser.add_argument("--algorithm", "--algorithm", help="Encryption algorithm to use to encrypt the string.")
    parser.add_argument("--list-algorithms", "--list_algorithms", help="List all encryption algorithms to encrypt your string.", action="store_true")
    parser.add_argument("--use-all-algorithms", "--use_all_algorithms", help="Encrypts your string with all (currently) supported encyrption algorithms.", action="store_true")
    parser.add_argument("--write-to-file", "--write_to_file", help="[Recommended] If present, it will store the string and encrypted string into a txt file.", action="store_true")
    parser.add_argument("--file", "--file", help="If you wish to write you string and hashed string into a file, enter a name for the .txt file")
    args = parser.parse_args()
    algorithm = str(args.algorithm)
    string = str(args.string)
    file_name = str(args.file)
    
    def encrypt_string_with_all_algorithms(string):
        global md5_hash, sha1_hash, sha224_hash, sha256_hash, sha384_hash, sha512_hash
        md5_hash = encryptor.md5(string)
        print(f"\nString: {string}\nMD5 value: {md5_hash}")
        sha1_hash = encryptor.sha1(string)
        print(f"\nString: {string}\nSHA1 value: {sha1_hash}")
        sha224_hash = encryptor.sha224(string)
        print(f"\nString: {string}\nSHA224 value: {sha224_hash}")
        sha256_hash = encryptor.sha256(string)
        print(f"\nString: {string}\nSHA256 value: {sha256_hash}")
        sha384_hash = encryptor.sha384(string)
        print(f"\nString: {string}\nSHA384 value: {sha384_hash}")
        sha512_hash = encryptor.sha512(string)
        print(f"\nString: {string}\nSHA512 value: {sha512_hash}\n")

    def write_to_file():
        while True:

            # If the user does add a ".txt" to the file name (to write the string and hash into a file), then it then check if the file does or does not exist.
            if file_name.endswith(".txt"):
                # If the file already exists, then it will put the file stream mode to append mode.
                if os.path.isfile(file_name):
                    file_stream = open(file_name, "a")
                    break
                
                # If the file does not exist, then it will put the file stream mode to write mode (to prevent errors).
                else:
                    file_stream = open(file_name, "w")
                    break
            # If the user does not add a ".txt" to the file name, then it will add the ".txt" when the file stream is created.
            elif not file_name.endswith(".txt"):
                if os.path.isfile(f"{file_name}.txt"):
                    file_stream = open(f"{file_name}.txt", "a")
                    break
                # If the file does not exist, then it will put the file stream mode to write mode (to prevent errors). And add the .txt extention to the file.
                else:
                    file_stream = open(f"{file_name}.txt", "w")
                    break
            
            else:
                raise IOError
           
        # If the user enters a valid encryption algorithm, then it will encyrpt the user's string and write the string, hash, and encyrption algorithm to the file.
        if algorithm.upper() in encryption_algorithms:
            if algorithm.upper() == "MD5":
                hashed_string = encryptor.md5(string)
                file_stream.write(
    f"""String: {string}
    Hash Algorithm: {algorithm.upper()}
    {algorithm.upper()} value: {hashed_string}

    """)
                file_stream.close()

            elif algorithm.upper() == "SHA1":
                hashed_string = encryptor.sha1(string)
                file_stream.write(
    f"""String: {string}
    Hash Algorithm: {algorithm.upper()}
    {algorithm.upper()} value: {hashed_string}

    """)
                file_stream.close()

            elif algorithm.upper() == "SHA224":
                hashed_string = encryptor.sha224(string)
                file_stream.write(
    f"""String: {string}
    Hash Algorithm: {algorithm.upper()}
    {algorithm.upper()} value: {hashed_string}

    """)
                file_stream.close()

            elif algorithm.upper() == "SHA256":
                hashed_string = encryptor.sha256(string)
                file_stream.write(
    f"""String: {string}
    Hash Algorithm: {algorithm.upper()}
    {algorithm.upper()} value: {hashed_string}

    """)
                file_stream.close()

            elif algorithm.upper() == "SHA384":
                hashed_string = encryptor.md5(string)
                file_stream.write(
    f"""String: {string}
    Hash Algorithm: {algorithm.upper()}
    {algorithm.upper()} value: {hashed_string}

    """)
                file_stream.close()

            elif algorithm.upper() == "SHA512":
                hashed_string = encryptor.sha512(string)
                file_stream.write(
    f"""String: {string}
    Hash Algorithm: {algorithm.upper()}
    {algorithm.upper()} value: {hashed_string}

    """)
                file_stream.close()


        elif args.use_all_algorithms:
            file_stream.write(
f"""String: {string}

MD5 value: {md5_hash}

SHA1 value: {sha1_hash}

SHA224 value: {sha224_hash}

SHA256 value: {sha256_hash}

SHA384 value: {sha384_hash}

SHA512 value: {sha512_hash}
""")
            file_stream.close()
        else:
            pass


    def encrypt_string():

        # If the user enters a valid encryption algorithm, then it will encyrpt the string and show the string and hash on the console window.
        if algorithm.upper() in encryption_algorithms:
            if algorithm.upper() == "MD5":
                hashed_string = encryptor.md5(string)
                print(f"\nString: {string}\n{algorithm.upper()} value: {hashed_string}\n")
            elif algorithm.upper() == "SHA1":
                hashed_string = encryptor.sha1(string)
                print(f"\nString: {string}\n{algorithm.upper()} value: {hashed_string}\n")
            
            elif algorithm.upper() == "SHA224":
                hashed_string = encryptor.sha224(string)
                print(f"\nString: {string}\n{algorithm.upper()} value: {hashed_string}\n")
            
            elif algorithm.upper() == "SHA256":
                hashed_string = encryptor.sha256(string)
                print(f"\nString: {string}\n{algorithm.upper()} value: {hashed_string}\n")

            elif algorithm.upper() == "SHA384":
                hashed_string = encryptor.sha384(string)
                print(f"\nString: {string}\n{algorithm.upper()} value: {hashed_string}\n")

            elif algorithm.upper() == "SHA512":
                hashed_string = encryptor.sha512(string)
                print(f"\nString: {string}\n{algorithm.upper()} value: {hashed_string}\n")
        else:
            pass

    encryption_algorithms = ["MD5", "SHA1", "SHA224", "SHA256","SHA384", "SHA512"]
    encryptor = encrypt.user_string()
    if args.list_algorithms:
        for item in encryption_algorithms:
            print(item)
        print()

    elif args.use_all_algorithms:
        if args.write_to_file:
            encrypt_string_with_all_algorithms(string)
            write_to_file()

        else:
            encrypt_string_with_all_algorithms(string)

    # If the user wants to have the hash and string saved into a file, then it will display the hash and string on the user's console. And it will have it writen into a seperate file.
    elif args.write_to_file:
        encrypt_string()
        write_to_file()

    # If the user does not want the string and hash saved into a file, then it will only show the string and encrypted hash onto the user's console.
    elif not args.write_to_file:
        encrypt_string()
        
    else:
        pass
 
# try:
main()

# except Exception as e:
#     print(f"\nError: {e}\n")

