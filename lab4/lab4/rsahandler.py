#!/usr/bin/env python
"""Implementation of RSAHandler class in charge of all RSA tasks in the system."""

import os
import binascii
import base64
from Crypto.PublicKey import RSA
from Crypto import Random

from library import Format
from library import START_HEADER
from library import END_HEADER

__author__ = "Dario Pavlovic"

class RSAHandler(Format):
    """Class provides methods for RSA encryption system."""
    def __init__(self):
        pass

    def import_key(self, public_file, private_file):
        """Inputs RSA keys from files and constructs and returns one Crypto key object."""
        public_fields = self.input_file(public_file)
        if ("Description" not in public_fields or 
                "Method" not in public_fields or
                "Modulus" not in public_fields or 
                "Public exponent" not in public_fields or
                "Key length" not in public_fields or 
                public_fields["Method"] != "RSA" or 
                public_fields["Description"] != "Public key"):
            raise Exception("Error reading RSA public key file.")

        private_fields = self.input_file(private_file)
        if ("Description" not in private_fields or 
                "Method" not in private_fields or
                "Modulus" not in private_fields or 
                "Private exponent" not in private_fields or
                "Key length" not in private_fields or 
                private_fields["Method"] != "RSA" or 
                private_fields["Description"] != "Private key"):
            raise Exception("Error reading RSA private key file.")       

        n = long(public_fields["Modulus"], 16)
        if n != long(private_fields["Modulus"], 16):
            raise Exception("RSA public and private keys don't match.")

        e = long(public_fields["Public exponent"], 16)
        d = long(private_fields["Private exponent"], 16)
        key = RSA.construct((n, e, d))
        return key    

    def export_key(self, public_file, private_file, rsa_key):
        """Output the Crypto key object to the files specified."""
        with open(public_file, "w") as f:
            f.write(START_HEADER + "\n")

            key = "Description"
            val = "Public key"
            f.write(self.gen_key_val(key, val))

            key = "Method"
            val = "RSA"
            f.write(self.gen_key_val(key, val))

            key = "Key length"
            val = str(self.convert_num_hex(rsa_key.n.bit_length()))
            f.write(self.gen_key_val(key, val))

            key = "Modulus"
            val = str(self.convert_num_hex(rsa_key.n))
            f.write(self.gen_key_val(key, val))

            key = "Public exponent"
            val = str(self.convert_num_hex(rsa_key.e))
            f.write(self.gen_key_val(key, val))

            f.write(END_HEADER + "\n")

        with open(private_file, "w") as f:
            f.write(START_HEADER + "\n")

            key = "Description"
            val = "Private key"
            f.write(self.gen_key_val(key, val))

            key = "Method"
            val = "RSA"
            f.write(self.gen_key_val(key, val))

            key = "Key length"
            val = str(self.convert_num_hex(rsa_key.n.bit_length()))
            f.write(self.gen_key_val(key, val))

            key = "Modulus"
            val = str(self.convert_num_hex(rsa_key.n))
            f.write(self.gen_key_val(key, val))

            key = "Private exponent"
            val = str(self.convert_num_hex(rsa_key.d))
            f.write(self.gen_key_val(key, val))

            f.write(END_HEADER + "\n")

    def generate_key(self, public_output, private_output, bits):
        """Generate a key and write it to a file. bits have to be >= 1024."""
        key = RSA.generate(bits)
        self.export_key(public_output, private_output, key)
        return key

    def import_public_key(self, filename):
        """Imports an RSA public key from a file."""
        fields = self.input_file(filename)
        if ("Description" not in fields or 
                "Method" not in fields or
                "Modulus" not in fields or 
                "Public exponent" not in fields or
                "Key length" not in fields or 
                fields["Method"] != "RSA" or 
                fields["Description"] != "Public key"):
            raise Exception("Error reading RSA public key file.")

        # print(fields["Modulus"])
        n = long(fields["Modulus"], 16)
        # print(n)
        e = long(fields["Public exponent"], 16)
        return RSA.construct((n, e))

    def encrypt(self, public_key_path, data, output_file=None):
        """Does RSA encryption of data, returns the encrypted data 
        and writes it to the output file if given.
        """
        key = self.import_public_key(public_key_path)
        cript = key.encrypt(data, 32)[0]
        if output_file != None:
            self.__output_encrypted(cript, key.n.bit_length(), output_file)

        return cript

    def decrypt(self, pub_key, priv_key, data, output_file=None):
        """Decrypts data and returns it. Outputs it to the file if given."""
        key = self.import_key(pub_key, priv_key)
        decrypt = key.decrypt(data)
        if output_file != None:
            with open(output_file, "w") as f:
                f.write(decrypt)

        return decrypt

    def decrypt_file(self, pub_key, priv_key, file, output_file=None):
        """Decrypts a file and returns it. Outputs it to the file if given."""
        key = self.import_key(pub_key, priv_key)
        data = self.__input_encrypted(file)
        
        decrypt = key.decrypt(data)
        if output_file != None:
            with open(output_file, "w") as f:
                f.write(decrypt)

        return decrypt

    def sign(self, key, hash):
        """Sign a hash with key and return the signature in long format."""
        return key.sign(hash, 0)[0]

    def verify(self, key, signature, hash):
        """Verify a signature with key."""
        return key.verify(hash, (signature, ))

    def __output_encrypted(self, data, key_len, filename):
        """Output the encrypted data into a file."""
        with open(filename, "w") as f:
            f.write(START_HEADER + "\n")

            key = "Description"
            val = "Crypted file"
            f.write(self.gen_key_val(key, val))

            key = "Method"
            val = "RSA"
            f.write(self.gen_key_val(key, val))

            # key = "Key length"
            # val = str(self.convert_num_hex(key_len))
            # f.write(self.gen_key_val(key, val))

            key = "Data"
            val = base64.b64encode(data)
            f.write(self.gen_key_val(key, val))

            f.write(END_HEADER + "\n")

    def __input_encrypted(self, filename):
        """Input the encrypted data from a file and return it as a string."""
        fields = self.input_file(filename)

        if ("Description" not in fields or "Method" not in fields or
                "Data" not in fields or fields["Method"] != "RSA"):
            raise Exception("RSA crypted file not formated correctly.")

        data = fields["Data"]
        # iv = fields["IV"]
        return base64.b64decode(data)
