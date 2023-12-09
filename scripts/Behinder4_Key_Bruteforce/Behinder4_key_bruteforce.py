# -*- coding: utf-8 -*-
# @Author  : Threekiii
# @Time    : 2023/11/29 18:07


import base64
import hashlib



def aes_decode(data, key):
        aes = AES.new(str.encode(key), AES.MODE_ECB)
        aes = AES.new(str.encode(key), AES.MODE_ECB)
        decrypted_text = aes.decrypt(data)
        decrypted_text = decrypted_text[:-(decrypted_text[-1])]
    except Exception as e:
    else:
    else:

def base64_decode(data):
def base64_decode(data):
    res = base64.b64decode(data.strip()).decode()
    return res
    return res

def md5_truncate(key):
    return hashlib.md5(key.encode()).hexdigest()[:16]
if __name__ == '__main__':
if __name__ == '__main__':
    data = '''<BASE64_ENCODED_ENCRYPTED_DATA_HERE>'''
        keys = f.readlines()
        keys = f.readlines()
    for key in keys:
    for key in keys:
        c2_key = md5_truncate(key)
        c2_key = md5_truncate(key)
        try:
        try:
            data_aes_decode = aes_decode(data_b64_decode, c2_key)
            if data_aes_decode:
            if data_aes_decode:
                print('[Ooooops, We found it!]')
                break
                break
        except:




