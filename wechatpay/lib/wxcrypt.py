# -*- coding:utf-8 -*-

"""
对小程序获取的用户信息解密代码.
"""
import base64
import json
from Crypto.Cipher import AES


class WXBizDataCrypt:
    def __init__(self, appid, session_key):
        self.appid = appid
        self.session_key = session_key

    def decrypt(self, encrypted_data, iv):
        '''
        aes decode
        将加密后的信息解密
        @param encrypted_data: 包括敏感数据在内的完整用户信息的加密数据
        @param iv: 加密算法的初始向量
        @return: 解密后数据
        '''
        print('raw session_key: %s \n encrypted:%s \n iv:%s\n ---' % (self.session_key, encrypted_data, iv))
        session_key = base64.b64decode(self.session_key)
        encrypted_data = base64.b64decode(encrypted_data)
        iv = base64.b64decode(iv)
        print('session_key: %s \n encrypted:%s \n iv:%s' % (session_key, encrypted_data, iv))
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        print('cipher:%s' % cipher)
        dcr = cipher.decrypt(encrypted_data)
        print('dcr:%s' % dcr)
        raw = self._unpad(dcr)
        print('raw:%s' % raw)
        decrypted = json.loads(raw.decode())
        if decrypted['watermark']['appid'] != self.appid:
            raise Exception('Invalid Buffer')
        return decrypted

    def _unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]
