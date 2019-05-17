#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import time
import urllib.request
import hmac
import hashlib
import binascii
import base64


class Auth(object):
    def __init__(self, cred):
        self.cred = cred

    def app_sign(self, bucket, cos_path, expired, upload_sign=True):
        app_id = self.cred.get_appid()
        secret_id = self.cred.get_secret_id()
        now = int(time.time())
        rdm = random.randint(0, 9999999999)
        cos_path = urllib.request.quote(cos_path.encode('utf8'), '~/')
        if upload_sign:
            fileid = '/%s/%s/%s' % (app_id, bucket, cos_path)
        else:
            fileid = cos_path

        if expired != 0 and expired < now:
            expired = now + expired

        sign_tuple = (app_id, bucket, secret_id, expired, now, rdm, fileid)
        plain_text = 'a=%s&b=%s&k=%s&e=%d&t=%d&r=%d&f=%s' % sign_tuple
        print('sign_plaintext', plain_text)
        secret_key = self.cred.get_secret_key().encode('utf8')
        hmac_digest = hmac.new(secret_key, plain_text.encode('utf-8'), hashlib.sha1).hexdigest()
        sign_hex = binascii.unhexlify(hmac_digest) + plain_text.encode('utf-8')
        sign_base64 = base64.b64encode(sign_hex)
        return sign_base64.decode('utf-8')

    def sign_once(self, bucket, cos_path):
        """单次签名(针对删除和更新操作)

        :param bucket: bucket名称
        :param cos_path: 要操作的cos路径, 以'/'开始
        :return: 签名字符串
        """
        return self.app_sign(bucket, cos_path, 0)

    def sign_more(self, bucket, cos_path, expired):
        """多次签名(针对上传文件，创建目录, 获取文件目录属性, 拉取目录列表)

        :param bucket: bucket名称
        :param cos_path: 要操作的cos路径, 以'/'开始
        :param expired: 签名过期时间, UNIX时间戳, 如想让签名在30秒后过期, 即可将expired设成当前时间加上30秒
        :return: 签名字符串
        """
        return self.app_sign(bucket, cos_path, expired, False)

    def sign_download(self, bucket, cos_path, expired):
        """下载签名(用于获取后拼接成下载链接，下载私有bucket的文件)

        :param bucket: bucket名称
        :param cos_path: 要下载的cos文件路径, 以'/'开始
        :param expired:  签名过期时间, UNIX时间戳, 如想让签名在30秒后过期, 即可将expired设成当前时间加上30秒
        :return: 签名字符串
        """
        return self.app_sign(bucket, cos_path, expired, False)
