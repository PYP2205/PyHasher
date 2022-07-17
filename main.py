"""
PyHasher

Programmed by: Paramon Yevstigneyev
Programmed in: Python 3.8.10 (64-Bit)

Description:
This is a Python program used for hashing and salting a string
into any hashing algorithm you select.
"""


def main():
    import hash
    import argparse
    import os


    parser = argparse.ArgumentParser()
	# Sets a descriptiption of the program, when the user enters "--help" or "-h" it will display the decription.
    parser.description = "Securly hash your strings with (almost) any hashion algorithm."
	# Stores the string that will be hashed.
    parser.add_argument("--string","--string", help="String to hash.")
	# Stores the algorithm name specifed by the user, to hash the string.
    parser.add_argument("--algorithm", "--algorithm", help="Hashing algorithm to use to hash the string.")
    # Stores the salt to add to the hashed string.
    parser.add_argument("--salt", "--salt", help="If specifed, this will make your hashed string (possibly) more secure [Recommended]")
	# Lists all algorithms that can be used to hash a string.
    parser.add_argument("--list-algorithms", "--list_algorithms", help="List all hashing algorithms to hash your string.", action="store_true")
	# Used for hashing the user's string with all (currently supported) hashion algorithms.
    parser.add_argument("--use-all-algorithms", "--use_all_algorithms", help="Hashes your string with all (currently) supported hashing algorithms.", action="store_true")
	# Writes the user's string(s), hashing algorithm, and hashed string into a .txt file.
    parser.add_argument("--write-to-file", "--write_to_file", help="[Recommended] When called, it will store the string and hashed string(s) into a .txt file.")
    args = parser.parse_args()
    
    algorithm = str(args.algorithm)
    string = str(args.string)
    salt = args.salt
    if salt == None:
        hash_salted = False
    else:
        salt = str(salt)
        hash_salted = True 
    
    file_name = args.write_to_file

    if file_name != "" and file_name != "None" and file_name != None:
        file_name = str(file_name)
        write_hash_to_file = True

    else:
        write_hash_to_file = False
    
	# Used for hashing string(s) into all supported hashion algorithms.
    def hash_string_with_all_algorithms(string, salt):
        # Makes the hashes global, to prevent exceptions from being raised when the user wants the hashes in a .txt file.
        global md5_hash, salted_md5_hash, sha1_hash, salted_sha1_hash, sha224_hash, salted_sha224_hash, sha256_hash, salted_sha256_hash, sha384_hash, salted_sha384_hash, sha512_hash, salted_sha512_hash
        
        # Creates the hashes and shows them to the user's console.
        if hash_salted:
            md5_hash, salted_md5_hash = hasher.md5(string, salt)
            sha1_hash, salted_sha1_hash = hasher.sha1(string, salt)
            sha224_hash, salted_sha224_hash = hasher.sha224(string, salt)
            sha256_hash, salted_sha256_hash = hasher.sha256(string, salt)
            sha384_hash, salted_sha384_hash = hasher.sha384(string, salt)
            sha512_hash, salted_sha512_hash = hasher.sha512(string, salt)
            print(f"\nString: {string}\n\nSalt: {salt}\n\nMD5 value: {md5_hash}\n\nSalted MD5 value: {salted_md5_hash}\n\nSHA-1 value: {sha1_hash}\n\nSalted SHA-1 value: {salted_sha1_hash}\n\nSHA-224 value: {sha224_hash}\n\nSalted SHA-224 value: {salted_sha224_hash}\n\nSHA-256 value: {sha256_hash}\n\nSalted SHA-256: {salted_sha256_hash}\n\nSHA-384 value: {sha384_hash}\n\nSalted SHA-384 value: {salted_sha384_hash}\n\nSHA-512 value: {sha512_hash}\n\nSalted SHA-512 value: {salted_sha512_hash}\n")
        else:
            md5_hash = hasher.md5(string, salt=None)
            sha1_hash = hasher.sha1(string, salt=None)
            sha224_hash = hasher.sha224(string, salt=None)
            sha256_hash = hasher.sha256(string, salt=None)
            sha384_hash = hasher.sha384(string, salt=None)
            sha512_hash = hasher.sha512(string, salt=None)
            print(f"\nString: {string}\n\nMD5 value: {md5_hash}\n\nSHA-1 value: {sha1_hash}\n\nSHA-224 value: {sha224_hash}\n\nSHA-256 value: {sha256_hash}\n\nSHA-384 value: {sha384_hash}\n\nSHA-512 value: {sha512_hash}\n")
	# Used for writing the user's string(s), hash(es), and hashing algorithm(s).
    def write_to_file():

        while True:

            # If the user does add a ".txt" to the file name (to write the string and hash into a file), then it will check if the file does or does not exist.
            if file_name.endswith(".txt") and file_name != "":

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
                break

           
        # If the user enters a valid hashion algorithm, then it will encyrpt the user's string and write the string, hash, and encyrption algorithm to the file.
        if algorithm.upper() in hashion_algorithms:
            if algorithm.upper() == "MD5":
                
                if hash_salted:
                    hashed_string, salted_hash = hasher.md5(string, salt)
                    file_stream.write(
f"""String: {string}
Salt: {salt}
MD5 value: {hashed_string}
Salted MD5 value: {salted_hash}

""")
                else:
                    hashed_string = hasher.md5(string, salt=None)
                    file_stream.write(
f"""String: {string}
MD5 value: {hashed_string}

""")
                file_stream.close()

            elif algorithm.upper() == "SHA1":
                if hash_salted:
                    hashed_string, salted_hash = hasher.sha1(string, salt)
                    file_stream.write(
f"""String: {string}
Salt: {salt}
SHA-1 value: {hashed_string}
Salted SHA-1 value: {salted_hash}

""")
                else:
                    hashed_string = hasher.sha1(string, salt=None)
                    file_stream.write(
f"""String: {string}
SHA-1 value: {hashed_string}

""")
                file_stream.close()

            elif algorithm.upper() == "SHA224":
                if hash_salted:
                    hashed_string, salted_hash = hasher.sha224(string, salt)
                    file_stream.write(
f"""String: {string}
Salt: {salt}
SHA-224 value: {hashed_string}
Salted SHA-224 value: {salted_hash}

""")
                else:
                    hashed_string = hasher.sha224(string, salt=None)
                    file_stream.write(
f"""String: {string}
SHA-224 value: {hashed_string}

""")
                file_stream.close()

            elif algorithm.upper() == "SHA256":
                if hash_salted:
                    hashed_string, salted_hash = hasher.sha256(string, salt)
                    file_stream.write(
f"""String: {string}
Salt: {salt}
SHA-256 value: {hashed_string}
Salted SHA-256 value: {salted_hash}

""")
                else:
                    hashed_string = hasher.sha256(string, salt=None)
                    file_stream.write(
f"""String: {string}
SHA-256 value: {hashed_string}

""")
                file_stream.close()

            elif algorithm.upper() == "SHA384":
                if hash_salted:
                    hashed_string, salted_hash = hasher.sha384(string, salt)
                    file_stream.write(
f"""String: {string}
Salt: {salt}
SHA-384 value: {hashed_string}
Salted SHA-384 value: {salted_hash}

""")
                else:
                    hashed_string = hasher.sha384(string, salt=None)
                    file_stream.write(
f"""String: {string}
SHA-384 value: {hashed_string}

""")
                file_stream.close()

            elif algorithm.upper() == "SHA512":
                if hash_salted:
                    hashed_string, salted_hash = hasher.sha512(string, salt)
                    file_stream.write(
    f"""String: {string}
    Salt: {salt}
    SHA-512 value: {hashed_string}
    Salted SHA-512 value: {salted_hash}

    """)
                else:
                    hashed_string = hasher.sha512(string, salt=None)
                file_stream.write(
f"""String: {string}
SHA-512 value: {hashed_string}

""")
                file_stream.close()


        elif args.use_all_algorithms:
            if hash_salted:
                file_stream.write(
f"""String: {string}
Salt: {salt}

MD5 value: {md5_hash}
Salted MD5 value: {salted_md5_hash}

SHA-1 value: {sha1_hash}
Salted SHA-1 value: {salted_sha1_hash}

SHA-224 value: {sha224_hash}
Salted SHA-224 value: {salted_sha224_hash}

SHA-256 value: {sha256_hash}
Salted SHA-256 value: {salted_sha256_hash}

SHA-384 value: {sha384_hash}
Salted SHA-384 value: {salted_sha384_hash}

SHA-512 value: {sha512_hash}
Salted SHA-512 value: {salted_sha512_hash}

""")
            else:
                file_stream.write(
f"""String: {string}

MD5 value: {md5_hash}
SHA-1 value: {sha1_hash}
SHA-224 value: {sha224_hash}
SHA-256 value: {sha256_hash}
SHA-384 value: {sha384_hash}
SHA-512 value: {sha512_hash}

""")
            file_stream.close()
        else:
            pass

	# Used for hashing a user's string, and displaying the string, hash, and algorithm used.
    def hash_string():

        # If the user enters a valid hashion algorithm, then it will encyrpt the string and show the string and hash on the console window.
        if algorithm.upper() in hashion_algorithms:
            if algorithm.upper() == "MD5":
                if hash_salted:
                    hashed_string, salted_hash = hasher.md5(string, salt)
                    print(f"\nString: {string}\nSalt: {salt}\n\n{algorithm.upper()} value: {hashed_string}\nSalted {algorithm.upper()} value: {salted_hash}\n")
                    
                else:
                    hashed_string = hasher.md5(string, salt=None)
                    print(f"\nString: {string}\n{algorithm.upper()} value: {hashed_string}\n")
                    
            elif algorithm.upper() == "SHA1":
                if hash_salted:
                    hashed_string, salted_hash = hasher.sha1(string, salt)
                    print(f"\nString: {string}\nSalt: {salt}\n\n{algorithm.upper()} value: {hashed_string}\nSalted {algorithm.upper()} value: {salted_hash}\n")

                else:
                    hashed_string = hasher.sha1(string, salt=None)
                    print(f"\nString: {string}\n{algorithm.upper()} value: {hashed_string}\n")
            
            elif algorithm.upper() == "SHA224":
                if hash_salted:
                    hashed_string, salted_hash = hasher.sha224(string, salt)
                    print(f"\nString: {string}\nSalt: {salt}\n\n{algorithm.upper()} value: {hashed_string}\nSalted {algorithm.upper()} value: {salted_hash}\n")

                else:
                    hashed_string = hasher.sha224(string, salt=None)
                    print(f"\nString: {string}\n{algorithm.upper()} value: {hashed_string}\n")
            
            elif algorithm.upper() == "SHA256":
                if hash_salted:
                    hashed_string, salted_hash = hasher.sha256(string, salt)
                    print(f"\nString: {string}\nSalt: {salt}\n\n{algorithm.upper()} value: {hashed_string}\nSalted {algorithm.upper()} value: {salted_hash}\n")

                else:
                    hashed_string = hasher.sha256(string, salt=None)
                    print(f"\nString: {string}\n{algorithm.upper()} value: {hashed_string}\n")

            elif algorithm.upper() == "SHA384":
                if hash_salted:
                    hashed_string, salted_hash = hasher.sha384(string, salt)
                    print(f"\nString: {string}\nSalt: {salt}\n\n{algorithm.upper()} value: {hashed_string}\nSalted {algorithm.upper()} value: {salted_hash}\n")

                else:
                    hashed_string = hasher.sha384(string, salt=None)
                    print(f"\nString: {string}\n{algorithm.upper()} value: {hashed_string}\n")

            elif algorithm.upper() == "SHA512":
                if hash_salted:
                    hashed_string, salted_hash = hasher.sha512(string, salt)
                    print(f"\nString: {string}\nSalt: {salt}\n\n{algorithm.upper()} value: {hashed_string}\nSalted {algorithm.upper()} value: {salted_hash}\n")

                else:
                    hashed_string = hasher.sha512(string, salt=None)
                    print(f"\nString: {string}\n{algorithm.upper()} value: {hashed_string}\n")
        else:
            pass
	
	# Stores (currently supported) names of hashing algorithms, which is used to list out what algorithms can be used.
    hash_algorithms = ["MD5", "SHA1", "SHA224", "SHA256","SHA384", "SHA512"]
	
	# Creates hasher, for hashing string(s).
    hasher = hash.user_string()
    if args.list_algorithms:
        for algorithm in hash_algorithms:
            print(algorithm)
        print()

    elif args.use_all_algorithms:
        if write_hash_to_file:
            if hash_salted:
                hash_string_with_all_algorithms(string, salt)
                write_to_file()
            else:
                hash_string_with_all_algorithms(string, salt=None)
                write_to_file()

        elif not write_hash_to_file:
            if hash_salted:
                hash_string_with_all_algorithms(string, salt)
            else:
                hash_string_with_all_algorithms(string, salt=None)

    # If the user wants to have the hash and string saved into a file, then it will display the hash and string on the user's console. And it will have it writen into a seperate file.
    elif write_hash_to_file:
        hash_string()
        write_to_file()

    # If the user does not want the string and hash saved into a file, then it will only show the string and hashed hash onto the user's console.
    elif not write_hash_to_file:
        hash_string()
        
    else:
        pass
 
try:
    main()

except Exception as e:
 	print(f"\nError: {e}\n")
