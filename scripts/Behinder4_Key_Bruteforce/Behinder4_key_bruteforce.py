# -*- coding: utf-8 -*-
# @Author  : Threekiii
# @Time    : 2023/11/29 18:07
# @Function: Brute force of Behinder4 secret key

import base64
import hashlib
from Crypto.Cipher import AES


def aes_decode(data, key):
    try:
        aes = AES.new(str.encode(key), AES.MODE_ECB)
        decrypted_text = aes.decrypt(data)
        decrypted_text = decrypted_text[:-(decrypted_text[-1])]
    except Exception as e:
        print(e)
    else:
        return decrypted_text.decode()

def base64_decode(data):
    res = base64.b64decode(data.strip()).decode()
    print(res)
    return res

def md5_truncate(key):
    return hashlib.md5(key.encode()).hexdigest()[:16]

if __name__ == '__main__':
    data = '''<BASE64_ENCODED_ENCRYPTED_DATA_HERE>'''
    with open('keys.txt','r',encoding='utf-8') as f:
        keys = f.readlines()

    for key in keys:
        key = key.strip()
        c2_key = md5_truncate(key)
        print('[CURRENT KEY]\t{} {}'.format(key,c2_key))
        try:
            data_b64_decode = base64.b64decode(data.strip())
            data_aes_decode = aes_decode(data_b64_decode, c2_key)
            if data_aes_decode:
                print('[Ooooops, We found it!]')
                print(data_aes_decode)
                break
        except:
            pass



