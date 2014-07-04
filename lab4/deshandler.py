#!/usr/bin/env python
"""Implementation of DESHandler class in charge of all DES tasks in the system."""

import os
import binascii
import base64
from Crypto.Cipher import DES
from Crypto import Random

from library import Format
from library import START_HEADER
from library import END_HEADER

__author__ = "Dario Pavlovic"

class DESHandler(Format):
    """Class provides methods for DES encryption system. Uses CBC method."""
    def __init__(self):
        pass

    def import_key(self, filename):
        """Inputs DES key from a file."""
        fields = self.input_file(filename)
        if ("Description" not in fields or "Method" not in fields or
                "Secret key" not in fields or fields["Method"] != "DES"):
            raise Exception("Error reading DES key file.")

        key = fields["Secret key"]
        key = binascii.unhexlify(key)
        if len(key) != 8:
            raise Exception("DES key incorrect.")

        return key

    def export_key(self, filename, des_key):
        """Output the key to the file specified by name."""
        with open(filename, "w") as f:
            f.write(START_HEADER + "\n")

            key = "Description"
            val = "Secret key"
            f.write(self.gen_key_val(key, val))

            key = "Method"
            val = "DES"
            f.write(self.gen_key_val(key, val))

            key = "Secret key"
            val = binascii.hexlify(des_key)
            f.write(self.gen_key_val(key, val))

            f.write(END_HEADER + "\n")

    def generate_key(self, filename):
        """Generates a random DES key and writes it to a file."""
        key = os.urandom(8)
        self.export_key(filename, key)

    def encrypt(self, key_file, input_file, output_file=None):
        """Does encryption of the input file and stores it
        in the output file in the used format.
        """
        key = self.import_key(key_file)
        iv = Random.new().read(DES.block_size)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        data = open(input_file, "r").read()
        data = self.__pad(data)
        data = cipher.encrypt(data)

        if output_file != None:
            self.__output_encrypted(data, output_file, iv)
        return data

    def decrypt(self, key_file, input_file, output_file=None):
        """Decrypts the input file and stores the data in the output file."""
        data = self.__input_encrypted(input_file)
        iv = data[:DES.block_size]
        key = self.import_key(key_file)
        cipher = DES.new(key, DES.MODE_CBC, iv)

        data = self.__unpad(cipher.decrypt(data[DES.block_size:]))
        if output_file != None:
            with open(output_file, "w") as f:
                f.write(data)
        return data

    def __output_encrypted(self, data, filename, iv):
        """Output the encrypted data into a file."""
        with open(filename, "w") as f:
            f.write(START_HEADER + "\n")

            key = "Description"
            val = "Crypted file"
            f.write(self.gen_key_val(key, val))

            key = "Method"
            val = "DES"
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
                fields["Method"] != "DES"):
            raise Exception("DES crypted file not formated correctly.")

        data = fields["Data"]
        iv = fields["IV"]
        return binascii.unhexlify(iv) + base64.b64decode(data)

    def __pad(self, data):
        """Adds the padding to the original message before crypting."""
        return data + (DES.block_size - len(data) % DES.block_size) * \
            chr(DES.block_size - len(data) % DES.block_size)

    def __unpad(self, data):
        """Removes the padding from a decrypted message."""
        return data[0:-ord(data[-1])]
