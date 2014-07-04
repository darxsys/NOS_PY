#!/usr/bin/env python

import sys
import binascii

from aeshandler import AESHandler
from sha1handler import SHA1Handler
from rsahandler import RSAHandler
from signature import Signature

def aes():
    print("Choose (E)ncryption, (D)ecryption or (K)ey generation.")
    opt = sys.stdin.readline().strip()

    aes = AESHandler()

    if opt == "K":
        print("Output file please.")
        f = sys.stdin.readline().strip()
        print("Key length:")
        l = int(sys.stdin.readline().strip())
        try:
            aes.generate_key(f, l)
            print("Success")
        except:
            print("Error with AES key.")

    elif opt == "E":
        print("Input file:")
        f = sys.stdin.readline().strip()
        print("Key file:")
        k = sys.stdin.readline().strip()
        print("Output file:")
        o = sys.stdin.readline().strip()

        print(binascii.hexlify(aes.encrypt(k, f, o)))

    elif opt == "D":
        print("Input file:")
        f = sys.stdin.readline().strip()
        print("Key file:")
        k = sys.stdin.readline().strip()

        print("")
        print("$$$$")
        print(aes.decrypt(k, f))
        print("$$$$")

    print("")
    return

def rsa():
    print("Choose (E)ncryption, (D)ecryption or (K)ey generation.")
    opt = sys.stdin.readline().strip()

    rsa = RSAHandler()

    if opt == "K":
        print("Public output file please.")
        pub = sys.stdin.readline().strip()
        print("Private output file please.")
        priv = sys.stdin.readline().strip()        
        print("Key length in bits:")
        l = int(sys.stdin.readline().strip())
        try:
            rsa.generate_key(pub, priv, l)
            print("Success")
        except:
            print("Error with RSA key.")

    elif opt == "E":
        print("Input file:")
        f = sys.stdin.readline().strip()
        print("Public key file:")
        k = sys.stdin.readline().strip()
        print("Output file:")
        o = sys.stdin.readline().strip()

        data = open(f, "r").read()
        print(binascii.hexlify(rsa.encrypt(k, data, o)))

    elif opt == "D":
        print("Input file:")
        f = sys.stdin.readline().strip()
        print("Pub key file:")
        pub = sys.stdin.readline().strip()
        print("Priv key file:")
        priv = sys.stdin.readline().strip()
        print("Output file:")
        o = sys.stdin.readline().strip()

        # data = open(f, "r").read()

        print("")
        print("$$$$")
        print(rsa.decrypt_file(pub, priv, f, o))
        print("$$$$")

    print("")
    return

def sha():
    sha = SHA1Handler()
    print("Input file to hash:")
    f = sys.stdin.readline().strip()
    print("Output file:")
    o = sys.stdin.readline().strip()

    print("")
    print("$$$$")
    print(binascii.hexlify(sha.hash(f, o)))
    print("$$$$")

    print("")

def env():
    print("(G)enerate or (O)pen")
    opt = sys.stdin.readline().strip()
    sig = Signature()

    if opt == "G":
        print("Data file:")
        f = sys.stdin.readline().strip()
        print("AES key:")
        aes = sys.stdin.readline().strip()
        print("Path to receiver public key:")
        pub = sys.stdin.readline().strip()
        print("Path to output:")
        out = sys.stdin.readline().strip()
        sig.generate_envelope(f, aes, pub, out)
        print("Success")
    elif opt == "O":
        print("Path to envelope:")
        e = sys.stdin.readline().strip()
        print("Path to pub key:")
        pub = sys.stdin.readline().strip()
        print("Path to priv key:")
        priv = sys.stdin.readline().strip()

        print("")
        print("$$$$")
        print(sig.open_envelope(e, pub, priv))
        print("$$$$")

    print("")
    return

def sig():
    print("(G)enerate or (V)erify")
    opt = sys.stdin.readline().strip()
    sig = Signature()

    if opt == "G":
        print("Path to data to sign:")
        f = sys.stdin.readline().strip()
        data = open(f, "r").read()
        print("Public key:")
        pub = sys.stdin.readline().strip()
        print("Priv key:")
        priv = sys.stdin.readline().strip()
        print("Output file:")
        out = sys.stdin.readline().strip()

        sig.generate_signature(f, data, pub, priv, out)
        print("Success")

    elif opt == "V":
        print("Path to data:")
        f = sys.stdin.readline().strip()
        print("Path to signature:")
        s = sys.stdin.readline().strip()
        print("Path to public key")
        pub = sys.stdin.readline().strip()

        data = open(f, "r").read()
        print("")
        print("$$$$")
        if sig.check_signature(s, data, pub) == True:
            print("OK.")
        else:
            print("Wrong signature.")
        print("$$$$")

    print("")
    return

def stamp():
    print("(G)enerate or (O)pen and check")
    opt = sys.stdin.readline().strip()
    sig = Signature()

    if opt == "G":
        print("Data:")
        f = sys.stdin.readline().strip()
        print("Path to aes key:")
        aes = sys.stdin.readline().strip()
        print("Path to A public key:")
        pub_A = sys.stdin.readline().strip()
        print("Path to A priv key:")
        priv_A = sys.stdin.readline().strip()
        print("Path to B public key:")
        pub_B = sys.stdin.readline().strip()
        print("Envelope output:")
        env = sys.stdin.readline().strip()
        print("Signature out:")
        s = sys.stdin.readline().strip()

        sig.digital_stamp(f, aes, pub_A, priv_A, pub_B, env, s)
        print("Success")

    elif opt == "O":
        print("Path to envelope:")
        env = sys.stdin.readline().strip()
        print("Path to  signature:")
        s = sys.stdin.readline().strip()
        print("Path to B public key:")
        pub_B = sys.stdin.readline().strip()
        print("Path to B priv key:")
        priv_B = sys.stdin.readline().strip()
        print("Path to A public key:")
        pub_A = sys.stdin.readline().strip()
        
        print("")
        print("$$$$")
        print(sig.open_check_stamp(env, s, pub_B, priv_B, pub_A))    
        print("$$$$")

    print("")
    return

def main():

    print("Choose option.")
    print("A - AES")
    print("R - RSA")
    print("S - SHA1")
    print("Envelope - E")
    print("Signature - S")
    print("Stamp - ST")
    print("")

    opt = sys.stdin.readline().strip()
    if opt == "A":
        aes()
    elif opt == "R":
        rsa()
    elif opt == "S":
        sha()
    elif opt == "E":
        env()
    elif opt == "S":
        sig()
    elif opt == "ST":
        stamp()
    else: return


if __name__ == "__main__":
    main()