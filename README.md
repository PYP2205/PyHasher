# PyHasher
A Python program for hashing a user string with commonly used encryption algorithms (MD5, SHA-1, SHA-256, etc.). To know what algorithms you can use for hashing strings, then you can list all encryption algorithms you can use for hashing the string. Then when you've decied which algorithm to use, then with 2 paramters and arguments you will encrypt a string with the algorithm provided.

# Instructions
From the latest release page, download the executable for your system. Currently Windows 10 and later, and Linux executables are supported (and been tested) for this program. I will be considering supporting portable executables for Mac devices. If you would like to run from the source, then in a terminal run:
* Windows: python main.py [arguments]
* Linux & Mac: python3 main.py [arguments]

# Usage
Please note that if you provide these arguments and parameters in any random order, then it will not cause any exception(s) to be raised.
* "--string" is used for storing the string that will be hashed [Required].
* "--algorithm" is used for specifying which hashing algorithm to use, for encrypting your string [Required for specifying an hashing algorithm].
* "--list-algorithms" is used for listing hashing algorithms that this program can (currently) hash strings with [Optional].
* "--use-all-algorithms" is used for hashing a string with all (currently supported) hashing algorithms [Optional, but required if you're not specifying one single algorithm].
* "--write-to-file" is used for writing the unencrypted string, encrypted string, and the hashing algorithm used to encrypt the string [Optional, but recommended. If specified enter a name of a file to write the string and hashes to].
* "--file" is used to specify the name of the file, that would store the strings and hashes you input [Deprecated].
