#!/usr/bin/env python
"""FER-CS-NOS
Defines superclass for classes that implement a system for digital signature and digital envelopes.
It uses and handles a custom file format to store and read all necessary information.
"""

import re

__author__ = "Dario Pavlovic"

START_HEADER = "---BEGIN OS2 CRYPTO DATA---"
END_HEADER = "---END OS2 CRYPTO DATA---"

class Format(object):
    """Superclass that stores all the common methods for all other format classes.
    Should not be used by itself.
    """
    def __init__(self):
        pass

    def input_file(self, filename):
        """Goes through a file and stores the fields in a dictionary and then returns it.
        Throws an Exception if file is not well formated.
        """
        with open(filename, "r") as f:
            ret = {}
            input_data = False
            while input_data == False:
                line = f.readline().strip()
                if line == START_HEADER:
                    input_data = True

            if input_data == False:
                raise Exception("File not formatted correctly.")

            format_ok = False
            lines = f.readlines()
            i = 0
            end = len(lines)

            while i < end:
                # reached end of file
                if lines[i].strip() == END_HEADER:
                    format_ok = True
                    break

                if lines[i] == "\n":
                    i += 1
                    continue

                val = ""
                # remove ":"
                key = lines[i].strip()[:-1]
                i += 1
                # next line is not okay
                if i >= end or lines[i] == "\n" or lines[i][0:4] != "    ":
                    raise Exception("File not formatted correctly.")

                val = lines[i].strip()
                i += 1
                # print(key)
                while i < end and lines[i] != "\n" and lines[i][0:4] == "    ":
                    if key == "Method" or key == "Key length":
                        # for digital signatures and other things with multiple keys
                        val += ";"
                    val += lines[i].strip()
                    i += 1

                if val == "":
                    raise Exception("File not formatted correctly.")

                ret[key] = val

            if format_ok == False:
                raise Exception("File not formatted correctly.")
            return ret

    def gen_key_val(self, key, val):
        """Function generates a key:value string according to the specified
        format. It converts numeric vals to hex first. This is used so that other
        methods don't have to worry about the output format of the file they are
        writing to so this can easily be changed.
        """
        ret = str(key) + ":" + "\n"
        if len(val) > 60:
            ret += "    " + re.sub("(.{60})", "\\1\n    ", val, 0, re.DOTALL) + "\n"
        else:
            ret += "    " + str(val) + "\n"
        return ret

    def convert_num_hex(self, num):
        """Converts a number to its hex representation with leading zeroes."""
        return hex(num)[2:].zfill(2)
        