#!/usr/bin/env python

import sys
from itertools import izip, cycle
import base64

class cipher:
    def encrypt(self, data, key):
        # we're working with string data
        if ( isinstance(data, str) and isinstance(key, str) ):
            ciph = ''.join(chr(ord(data_str) ^ ord(key_str)) for (data_str, key_str) in izip(data, cycle(key)))
            return base64.encodestring(ciph).strip()
        else:
            print('Data and key must be string')
            sys.exit(0)

    def decrypt(self, data, key):
        # we're working with string data
        if ( isinstance(data, str) and isinstance(key, str) ):
            data = base64.decodestring(data)
            return ''.join(chr(ord(data_str) ^ ord(key_str)) for (data_str, key_str) in izip(data, cycle(key)))
        else:
            print('Data and key must be string')
            sys.exit(0)


### MAIN ###
if __name__ == '__main__':

    secret_msg = 'It is secret message'
    key = 'SuperKey'

    c = cipher()
    enc_data = c.encrypt(secret_msg, key)
    print('Encoded data (xored and base64 encoded): {}'.format(enc_data))
    dec_data = c.decrypt(enc_data, key)
    print('Decoded data: {}'.format(dec_data))
    # Verify
    if (dec_data == secret_msg):
        print('Decode successfully')
    else:
        print('Decode failed')

    sys.exit(1)
