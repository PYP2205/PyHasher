"""
Hash

Programmed by: Paramon Yevstigneyev
Programmed in: Python 3.8.10 (64-Bit)

Decription:
This is used to hash a string a user inputted, in a hashing algorithm the user selected.
"""

class user_string:
    """
    A method used for encrypting a string with
    common encryption algorithms.
    """

    # Used for hashing user strings.
    import hashlib

    def __init__(self):
        pass

    def md5(self, string, salt):
        """
        Hashes a string using the MD5 Hashing Algorithm.
        """
        
        # If the ueser does not specify any salt to add to their hash, then it will hash the string provided.
        if salt == None:
            self.md5_hasher = self.hashlib.md5()
            self.md5_hasher.update(string.encode("utf-8"))
            self.hashed_string = self.md5_hasher.hexdigest()
            return self.hashed_string
        
        # If the user does specify a salt to add to their hash, then it will combine the string and salt before it gets hashed. 
        # It will give the user a salted hash and a unsalted hash.
        else:
            self.md5_hasher = self.hashlib.md5()
            self.md5_hasher.update(string.encode("utf-8"))
            self.hashed_string = self.md5_hasher.hexdigest()
            self.md5_hasher = self.hashlib.md5()
            self.md5_hasher.update(f"{string}{salt}".encode("utf-8"))
            self.salted_hash = self.md5_hasher.hexdigest()
            return self.hashed_string, self.salted_hash


    def sha1(self, string, salt):
        """
        Hashes a string using the SHA-1 Hashing Algorithm.
        """
        
        # If the ueser does not specify any salt to add to their hash, then it will hash the string provided.
        if salt == None:
            self.sha1_hasher = self.hashlib.sha1()
            self.sha1_hasher.update(string.encode("utf-8"))
            self.hashed_string = self.sha1_hasher.hexdigest()
            return self.hashed_string
        
        # If the user does specify a salt to add to their hash, then it will combine the string and salt before it gets hashed. 
        # It will give the user a salted hash and a unsalted hash.
        else:
            self.sha1_hasher = self.hashlib.sha1()
            self.sha1_hasher.update(string.encode("utf-8"))
            self.hashed_string = self.sha1_hasher.hexdigest()
            self.sha1_hasher = self.hashlib.sha1()
            self.sha1_hasher.update(f"{string}{salt}".encode("utf-8"))
            self.salted_hash = self.sha1_hasher.hexdigest()
            return self.hashed_string, self.salted_hash


    def sha224(self, string, salt):
        """
        Hashes a string using the SHA-224 Hashing Algorithm.
        """
        
        # If the ueser does not specify any salt to add to their hash, then it will hash the string provided.
        if salt == None:
            self.sha224_hasher = self.hashlib.sha224()
            self.sha224_hasher.update(string.encode("utf-8"))
            self.hashed_string = self.sha224_hasher.hexdigest()
            return self.hashed_string
        
        # If the user does specify a salt to add to their hash, then it will combine the string and salt before it gets hashed. 
        # It will give the user a salted hash and a unsalted hash.
        else:
            self.sha224_hasher = self.hashlib.sha224()
            self.sha224_hasher.update(string.encode("utf-8"))
            self.hashed_string = self.sha224_hasher.hexdigest()
            self.sha224_hasher = self.hashlib.sha224()
            self.sha224_hasher.update(f"{string}{salt}".encode("utf-8"))
            self.salted_hashed = self.sha224_hasher.hexdigest()
            return self.hashed_string, self.salted_hash


    def sha256(self, string, salt):
        """
        Hashes a string using the SHA-256 Hashing Algorithm.
        """
        
        # If the ueser does not specify any salt to add to their hash, then it will hash the string provided.
        if salt == None:
            self.sha256_hasher = self.hashlib.sha256()
            self.sha256_hasher.update(string.encode("utf-8"))
            self.hashed_string = self.sha256_hasher.hexdigest()
            return self.hashed_string
        
        # If the user does specify a salt to add to their hash, then it will combine the string and salt before it gets hashed. 
        # It will give the user a salted hash and a unsalted hash.
        else:
            self.sha256_hasher = self.hashlib.sha256()
            self.sha256_hasher.update(f"{string}{salt}".encode("utf-8"))
            self.salted_hash = self.sha256_hasher.hexdigest()
            return self.hashed_string, self.salted_hash

    def sha384(self, string, salt):
        """
        Hashes a string using the SHA-384 Hashing Algorithm.
        """
        
        # If the ueser does not specify any salt to add to their hash, then it will hash the string provided.
        if salt == None:
            self.sha384_hasher = self.hashlib.sha384()
            self.sha384_hasher.update(string.encode("utf-8"))
            self.hashed_string = self.sha384_hasher.hexdigest()
            return self.hashed_string
        
        # If the user does specify a salt to add to their hash, then it will combine the string and salt before it gets hashed. 
        # It will give the user a salted hash and a unsalted hash.
        else:
            self.sha384_hasher = self.hashlib.sha384()
            self.sha384_hasher.update(string.encode("utf-8"))
            self.hashed_string = self.sha384_hasher.hexdigest()
            self.sha384_hasher = self.hashlib.sha384()
            self.sha384_hasher.update(f"{string}{salt}".encode("utf-8"))
            self.salted_hash = self.sha384_hasher.hexdigest()
            return self.hashed_string, self.salted_hash

    def sha512(self, string, salt):
        """
        Hashes a string using the SHA-512 Hashing Algorithm.
        """
        if salt == None:
            self.sha512_hasher = self.hashlib.sha512()
            self.sha512_hasher.update(string.encode("utf-8"))
            self.hashed_string = self.sha512_hasher.hexdigest()
            return self.hashed_string
        
        # If the user does specify a salt to add to their hash, then it will combine the string and salt before it gets hashed. 
        # It will give the user a salted hash and a unsalted hash.
        else:
            self.sha512_hasher = self.hashlib.sha512()
            self.sha512_hasher.update(string.encode("utf-8"))
            self.hashed_string = self.sha512_hasher.hexdigest()
            self.sha512_hasher = self.hashlib.sha512()
            self.sha512_hasher.update(f"{string}{salt}".encode("utf-8"))
            self.salted_hash = self.sha512_hasher.hexdigest()
            return self.hashed_string, self.salted_hash
