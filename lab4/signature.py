#!/usr/bin/env python
"""Implementation of Signature class in charge of generating digital signature, 
digital envelope and digital stamp."""

import binascii
import base64

from library import Format
from library import START_HEADER
from library import END_HEADER

import aeshandler
import rsahandler
import sha1handler

__author__ = "Dario Pavlovic"

class Signature(Format):
    """Stores methods for producing digital signatures, digital envelopes
    and digital stamps.
    """
    def __init__(self):
        pass

    def generate_envelope(self, path_data, path_aes, path_public, path_output):
        """Generates a digital envelope and writes it to a file."""
        aes = aeshandler.AESHandler()
        aes_key = aes.import_key(path_aes)

        rsa = rsahandler.RSAHandler()
        rsa_key = rsa.import_public_key(path_public)
        crypt = aes.encrypt(path_aes, path_data)
        crypt_key = rsa.encrypt(path_public, aes_key)

        self.__output_envelope(crypt, crypt_key, rsa_key.n.bit_length(), 
            len(aes_key), path_output, path_data, method="AES")

    def open_envelope(self, path_envelope, path_public, path_private, path_out=None):
        """Opens the envelope and decrypts the data inside."""
        (key, data) = self.__import_envelope(path_envelope)
        # decrypt the key
        rsa = rsahandler.RSAHandler()
        rsa_key = rsa.import_key(path_public, path_private)
        key = rsa_key.decrypt(key)
        # print (key)

        aes = aeshandler.AESHandler()
        data = aes.decrypt_raw(key, data)
        return data

    def generate_signature(self, name, data, public_path, private_path, output_path=None):
        """Sign the hash and output it to a file. Also returns the signature."""
        sha = sha1handler.SHA1Handler()
        h = sha.hash_raw(data)
        rsa = rsahandler.RSAHandler()
        key = rsa.import_key(public_path, private_path)
        sig = rsa.sign(key, h)

        if output_path != None:
            self.__output_signature(name, sig, key.n.bit_length(), output_path)

        return sig

    def check_signature(self, sig_path, data, public_path):
        """Verifies the signature and returns boolean flag indicating if it is okay or not."""
        sha = sha1handler.SHA1Handler()
        h = sha.hash_raw(data)

        sig = self.__import_signature(sig_path)
        rsa = rsahandler.RSAHandler()
        key = rsa.import_public_key(public_path)

        return rsa.verify(key, sig, h)

    def digital_stamp(self, path_data, path_aes, path_public, path_private, 
            path_public_other, path_envelope, path_out):
        """Generate digital envelope for the data and the digital signature for the envelope and store it all."""
        self.generate_envelope(path_data, path_aes, path_public_other, path_envelope)
        envelope = open(path_envelope, "r").read()
        self.generate_signature(path_envelope, envelope, path_public, path_private, path_out)

    def open_check_stamp(self, path_envelope, path_signature, path_other_public, path_other_private,
            path_public):
        """Checks the stamp and returns the decrypted data if everything is okay."""
        data = open(path_envelope, "r").read()
        if not self.check_signature(path_signature, data, path_public):
            print("Signature not okay.")
            return

        print("Signature verified. Returning data.")
        data = self.open_envelope(path_envelope, path_other_public, path_other_private)
        return data

    def __import_signature(self, path):
        """Inputs the crypted signature."""
        fields = self.input_file(path)
        if ("Description" not in fields or "Method" not in fields or
                "Key length" not in fields or 
                "Signature" not in fields):
            raise Exception("Error reading signature file.")    

        sig = long(fields["Signature"], 16)
        return sig

    def __output_signature(self, name, signature, rsa_len, path):
        """Output the signature to a file."""
        with open(path, "w") as f:
            f.write(START_HEADER + "\n")

            key = "Description"
            val = "Signature"
            f.write(self.gen_key_val(key, val))

            key = "File name"
            val = name
            f.write(self.gen_key_val(key, val))

            key = "Method"
            val = "SHA-1" + "\n    RSA"
            f.write(self.gen_key_val(key, val))

            key = "Key length"
            val = str(self.convert_num_hex(160))
            val += "\n    " + str(self.convert_num_hex(rsa_len))
            f.write(self.gen_key_val(key, val))

            key = "Signature"
            val = str(self.convert_num_hex(signature))
            f.write(self.gen_key_val(key, val))

            f.write(END_HEADER + "\n")

    def __import_envelope(self, path):
        """Opens the envelope and returns the tuple with key and data inside."""
        fields = self.input_file(path)
        if ("Description" not in fields or "Method" not in fields or
                "Key length" not in fields or 
                "Envelope data" not in fields or
                "Envelope crypt key" not in fields):
            raise Exception("Error reading envelope file.")

        data = base64.b64decode(fields["Envelope data"])
        key = binascii.unhexlify(fields["Envelope crypt key"])
        return (key, data)

    def __output_envelope(self, crypted_data, crypted_key, 
            rsa_len, key_len, output_file, data_file=None, method="AES"):
        """Outputs the digital envelope."""
        with open(output_file, "w") as f:
            f.write(START_HEADER + "\n")

            key = "Description"
            val = "Envelope"
            f.write(self.gen_key_val(key, val))

            if data_file != None:
                key = "File name"
                val = data_file
                f.write(self.gen_key_val(key, val))

            key = "Method"
            val = method + "\n    RSA"
            f.write(self.gen_key_val(key, val))

            key = "Key length"
            val = str(self.convert_num_hex(key_len))
            val += "\n    " + str(self.convert_num_hex(rsa_len))
            f.write(self.gen_key_val(key, val))

            key = "Envelope data"
            val = base64.b64encode(crypted_data)
            f.write(self.gen_key_val(key, val))

            key = "Envelope crypt key"
            val = binascii.hexlify(crypted_key)
            f.write(self.gen_key_val(key, val))

            f.write(END_HEADER + "\n")
