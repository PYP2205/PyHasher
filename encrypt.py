"""
Encrypt

Programmed by: Paramon Yevstigneyev
Programmed in: Python 3.8.10 (64-Bit)

Decription:
This is used to encrypt a string a user inputted, in an encryption algorithm the user selected.
"""

class user_string:
    """
    A method used for encrypting a string with
    common encryption algorithms.
    """

    # Used for encypting user strings.
    import hashlib    
    def __init__(self):
        pass

    def md5(self, string):
        """
        Encrypts a string using the MD5 Encryption Algorithm.
        """
        
        self.md5_hasher = self.hashlib.md5()
        self.md5_hasher.update(string.encode("utf-8"))
        self.hashed_string = self.md5_hasher.hexdigest()
        return self.hashed_string

    def sha1(self, string):
        """
        Encrypts a string using the SHA-1 Encryption Algorithm.
        """

        self.sha1_hasher = self.hashlib.sha1()
        self.sha1_hasher.update(string.encode("utf-8"))
        self.hashed_string = self.sha1_hasher.hexdigest()
        return self.hashed_string

    def sha224(self, string):
        """
        Encrypts a string using the SHA-224 Encryption Algorithm.
        """
        
        self.sha224_hasher = self.hashlib.sha224()
        self.sha224_hasher.update(string.encode("utf-8"))
        self.hashed_string = self.sha224_hasher.hexdigest()
        return self.hashed_string

    def sha256(self, string):
        """
        Encrypts a string using the SHA-256 Encryption Algorithm.
        """
        
        self.sha256_hasher = self.hashlib.sha256()
        self.sha256_hasher.update(string.encode("utf-8"))
        self.hashed_string = self.sha256_hasher.hexdigest()
        return self.hashed_string

    def sha384(self, string):
        """
        Encrypts a string using the SHA-384 Encryption Algorithm.
        """
        
        self.sha384_hasher = self.hashlib.sha384()
        self.sha384_hasher.update(string.encode("utf-8"))
        self.hashed_string = self.sha238_hasher.hexdigest()
        return self.hashed_string

    def sha512(self, string):
        """
        Encrypts a string using the SHA-512 Encryption Algorithm.
        """
        
        self.sha512_hasher = self.hashlib.sha212()
        self.sha512_hasher.update(string.encode("utf-8"))
        self.hashed_string = self.sha224_hasher.hexdigest()
        return self.hashed_string