#!/usr/bin/env python
"""Implementation of AESHandler class in charge of all AES tasks in the system."""

import os
import binascii
import base64
from Crypto.Cipher import AES
from Crypto import Random

from library import Format
from library import START_HEADER
from library import END_HEADER

__author__ = "Dario Pavlovic"

class AESHandler(Format):
    """Class provides methods for AES encryption system. Uses CBC method."""
    def __init__(self, key=None, filename=None):
        pass

    def import_key(self, filename):
        """Inputs AES key from a file. Raises an exception if the input file
        is not correctly formatted or values are missing."""
        fields = self.input_file(filename)

        if ("Description" not in fields or "Method" not in fields or
                "Key length" not in fields or 
                "Secret key" not in fields or
                fields["Method"] != "AES"):
            raise Exception("Error reading AES key file.")
        # print (fields)
        key = fields['Secret key']
        key = binascii.unhexlify(key)
        key_len = int(fields["Key length"], 16)
        if len(key) != key_len:
            raise Exception("AES key file contains false information.")
            
        return key

    def export_key(self, filename, aes_key):
        """Output the key to the file specified by name."""
        with open(filename, "w") as f:
            f.write(START_HEADER + "\n")

            key = "Description"
            val = "Secret key"
            f.write(self.gen_key_val(key, val))

            key = "Method"
            val = "AES"
            f.write(self.gen_key_val(key, val))

            key = "Key length"
            val = str(self.convert_num_hex(len(aes_key)))
            f.write(self.gen_key_val(key, val))

            key = "Secret key"
            val = binascii.hexlify(aes_key)
            f.write(self.gen_key_val(key, val))

            f.write(END_HEADER + "\n")

    def generate_key(self, filename, size):
        """Generates a random AES key of the given size in bytes
        and writes it to a file. Exception raised if size is not
        valid.
        """
        if size != 16 and size != 24 and size != 32:
            raise ValueError("AES key size not valid.")
        key = os.urandom(size)
        self.export_key(filename, key)
        return key

    def encrypt(self, key_file, input_file, output_file=None):
        """Does encryption of the input file and stores it
        in the output file in the used format.
        """
        key = self.import_key(key_file)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = open(input_file, "r").read()
        data = self.__pad(data)
        data = cipher.encrypt(data)

        if output_file != None:
            self.__output_encrypted(data, len(key), output_file, iv)
        return iv + data

    def decrypt(self, key_file, input_file, output_file=None):
        """Decrypts either an input file, returns the data 
        and stores the data in the output file if given.
        """
        data = self.__input_encrypted(input_file)
        iv = data[:AES.block_size]
        key = self.import_key(key_file)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        data = self.__unpad(cipher.decrypt(data[AES.block_size:]))
        if output_file != None:
            with open(output_file, "w") as f:
                f.write(data)
        return data

    def decrypt_raw(self, key, data):
        """Decrypts raw data and returns it."""
        iv = data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = cipher.decrypt(data[AES.block_size:])
        return self.__unpad(data)

    def __output_encrypted(self, data, key_len, filename, iv):
        """Output the encrypted data into a file."""
        with open(filename, "w") as f:
            f.write(START_HEADER + "\n")

            key = "Description"
            val = "Crypted file"
            f.write(self.gen_key_val(key, val))

            key = "Method"
            val = "AES"
            f.write(self.gen_key_val(key, val))

            key = "File name"
            val = filename
            f.write(self.gen_key_val(key, val))

            key = "IV"
            val = binascii.hexlify(iv)
            f.write(self.gen_key_val(key, val))

            key = "Data"
            val = base64.b64encode(data)
            # val = data
            f.write(self.gen_key_val(key, val))

            f.write(END_HEADER + "\n")

    def __input_encrypted(self, filename):
        """Input the encrypted data from a file and return it as a string."""
        fields = self.input_file(filename)

        if ("Description" not in fields or "Method" not in fields or
                "Data" not in fields or "IV" not in fields or
                fields["Method"] != "AES"):
            raise Exception("AES crypted file not formated correctly.")

        data = fields["Data"]
        iv = fields["IV"]
        return binascii.unhexlify(iv) + base64.b64decode(data)

    def __pad(self, data):
        """Adds the padding to the original message before crypting."""
        return data + (AES.block_size - len(data) % AES.block_size) *  \
            chr(AES.block_size - len(data) % AES.block_size)

    def __unpad(self, data):
        """Removes the padding from a decrypted message."""
        return data[0:-ord(data[-1])]
