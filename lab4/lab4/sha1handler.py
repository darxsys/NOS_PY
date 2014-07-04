#!/usr/bin/env python
"""Implementation of SHA1Handler class in charge of all SHA1 tasks in the system."""

import os
import binascii
import base64
from Crypto.Hash import SHA
from Crypto import Random

from library import Format
from library import START_HEADER
from library import END_HEADER

__author__ = "Dario Pavlovic"

class SHA1Handler(Format):
    """Class provides methods for SHA1 digest system."""
    def __init__(self):
        pass 

    def hash_raw(self, data):
        """Hash raw data and return the hash in binary format."""
        h = SHA.new(data)
        return h.digest()

    def hash(self, input_file, output_file=None):
        """Makes a hash of the input file and stores the result in the output
        file if given. Returns binary digest.
        """
        h = SHA.new()
        data = open(input_file, "r").read()
        h.update(data)
        digest = h.digest()

        if output_file != None:
            self.__output_hash(output_file, digest)

        return digest

    def __output_hash(self, filename, hash):
        with open(filename, "w") as f:
            f.write(START_HEADER + "\n")

            key = "Description"
            val = "Hash"
            f.write(self.gen_key_val(key, val))

            key = "Method"
            val = "SHA1"
            f.write(self.gen_key_val(key, val))

            key = "Data"
            val = binascii.hexlify(hash)
            f.write(self.gen_key_val(key, val))

            f.write(END_HEADER + "\n")