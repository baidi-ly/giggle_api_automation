import hashlib
import os
import re
from urllib import parse
import requests
import time

from config import RunConfig
from utils.TimeoutHTTPAdapter import TimeoutHTTPAdapter
from utils.rsa_manage import password_rsa, password_base64

DEFAULT_TIMEOUT = int(RunConfig.timeout)  # 单位是秒
base_url = RunConfig.baseurl
AUTH_KEY = RunConfig.AUTH_KEY
DeviceId = RunConfig.DeviceId


class BaseAPI:
    """框架公用方法"""

    def baseurl(self):
        return RunConfig.baseurl

    def get_user_account(self, file_name="account.txt"):
        '''获取人员帐号信息'''
        base_dir = os.path.abspath(__file__)
        base_dir = str(base_dir).split("test_case")[0]
        old_path = base_dir
        base = base_dir + '/test_data'
        os.chdir(base)
        user_file = open(file_name, 'r', encoding="UTF-8")
        users = user_file.readlines()
        names, emails, passwords, tokens = [], [], [], []
        for u in users:
            names.append(u.split(',')[0].strip())
            emails.append(u.split(',')[1].strip())
            passwords.append(u.split(',')[2].strip())
            tokens.append(u.split(',')[3].strip())
        os.chdir(old_path)
        return names, emails, passwords, tokens

    # http和https超时设置,默认30秒,也可传入timeout
    def http_timeout(self, timeout=DEFAULT_TIMEOUT):
        timeout = timeout or DEFAULT_TIMEOUT
        http = requests.Session()
        # 把配置复制给http和https请求
        adapter = TimeoutHTTPAdapter(timeout=timeout)
        http.mount("https://", adapter)
        http.mount("http://", adapter)
        return http

    def admin_login(self, email, password, DeviceType="web", **kwargs):
        """
        用户登录 - 邮箱密码
        :param email: 用户邮箱
        :param password: 用户密码   base64加密
        :param token: 可选，第三方登录token
        :param inviteByCode: 设备类型
        :param kwargs: 其他参数如token: 可选，第三方登录token
        :return:
        """
        # Create Data:  ?  2025-09-11
        # Update Date:  v.18.0  2025-09-11
        # Update Details:  1. 响应新增 `bindAccount` 字段
        url = "https://{0}/admin/login".format(base_url)
        password = password_base64(password)
        payload = {
            "email": email,
            "password": password
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        Deviceid = "8320afd7-9c41-402c-8136-d3b6a4e6401f"
        _Authtoken = f"{timestamp}{Deviceid}{RunConfig.AUTH_KEY}"
        Authtoken = hashlib.md5(_Authtoken.encode()).hexdigest()
        headers = {
            "Authtoken": Authtoken,  # Authtoken与Timestamp需要有对应关系
            "Deviceid": Deviceid,
            "DeviceType": DeviceType,  # android/ios/web
            "Timestamp": timestamp
        }
        response = self.http_timeout().request("POST", url, headers=headers, json=payload)
        error_msg = "用户登录 - 邮箱密码"
        assert response.status_code in [200,
                                        201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def login(self, email, password, DeviceType="web", **kwargs):
        """
        用户登录 - 邮箱密码
        :param email: 用户邮箱
        :param password: 用户密码   base64加密
        :param token: 可选，第三方登录token
        :param inviteByCode: 设备类型
        :param kwargs: 其他参数如token: 可选，第三方登录token
        :return:
        """
        # Create Data:  ?  2025-09-05
        # Update Date:  v.18.0  2025-09-08
        # Update Details:  1. 响应新增 `bindAccount` 字段
        url = "https://{0}/api/user/login".format(base_url)
        # password = parse.quote(password_rsa(password))
        password = password_base64(password)
        payload = {
            "email": email,
            "password": password
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        Deviceid = "8320afd7-9c41-402c-8136-d3b6a4e6401f"
        _Authtoken = f"{timestamp}{Deviceid}{RunConfig.AUTH_KEY}"
        Authtoken = hashlib.md5(_Authtoken.encode()).hexdigest()
        headers = {
            "Authtoken": Authtoken,    # Authtoken与Timestamp需要有对应关系
            "Deviceid": Deviceid,
            "DeviceType": DeviceType,    # android/ios/web
            "Timestamp": timestamp
        }
        response = self.http_timeout().request("POST", url, headers=headers, json=payload)
        error_msg = "用户登录 - 邮箱密码"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def loginByEmail(self, email, password, bindAccount, DeviceType="web"):
        """
        用户登录 - 邮箱验证码
        :param email:
        :param password:
        :param token:
        :param inviteByCode:
        :param kwargs: 其他参数如token: 可选，第三⽅登录token
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/user/login/email".format(base_url)
        password = password_base64(password)
        payload = {
            "email": email,
            "password": password,
            "bindAccount": bindAccount
        }
        timestamp = str(int(time.time() * 1000))
        Deviceid = "8320afd7-9c41-402c-8136-d3b6a4e6401f"
        _Authtoken = f"{timestamp}{Deviceid}{RunConfig.AUTH_KEY}"
        Authtoken = hashlib.md5(_Authtoken.encode()).hexdigest()
        headers = {
            "Authtoken": Authtoken,    # Authtoken与Timestamp需要有对应关系
            "Deviceid": Deviceid,
            "DeviceType": DeviceType,    # android/ios/web
            "Timestamp": timestamp
        }
        response = self.http_timeout().request("POST", url, headers=headers, json=payload)
        error_msg = "用户登录 - 邮箱验证码"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def loginByPhonePassword(self, email, password, bindAccount, DeviceType="web"):
        """
        用户登录 - 微信登录
        :param email:
        :param password:
        :param token:
        :param inviteByCode:
        :param kwargs:
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/user/login/phonePassword".format(base_url)
        password = password_base64(password)
        payload = {
            "email": email,
            "password": password,
            "bindAccount": bindAccount
        }
        timestamp = str(int(time.time() * 1000))
        Deviceid = "8320afd7-9c41-402c-8136-d3b6a4e6401f"
        _Authtoken = f"{timestamp}{Deviceid}{RunConfig.AUTH_KEY}"
        Authtoken = hashlib.md5(_Authtoken.encode()).hexdigest()
        headers = {
            "Authtoken": Authtoken,    # Authtoken与Timestamp需要有对应关系
            "Deviceid": Deviceid,
            "DeviceType": DeviceType,    # android/ios/web
            "Timestamp": timestamp
        }
        response = self.http_timeout().request("POST", url, headers=headers, json=payload)
        error_msg = "用户登录 - 微信登录"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def loginByPhone(self, email, password, bindAccount, DeviceType="web"):
        """
        用户登录 - 手机验证码登录
        :param email:
        :param password:
        :param token:
        :param inviteByCode:
        :param kwargs:
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/user/login/phone".format(base_url)
        password = password_base64(password)
        payload = {
            "email": email,
            "password": password,
            "bindAccount": bindAccount
        }
        timestamp = str(int(time.time() * 1000))
        Deviceid = "8320afd7-9c41-402c-8136-d3b6a4e6401f"
        _Authtoken = f"{timestamp}{Deviceid}{RunConfig.AUTH_KEY}"
        Authtoken = hashlib.md5(_Authtoken.encode()).hexdigest()
        headers = {
            "Authtoken": Authtoken,    # Authtoken与Timestamp需要有对应关系
            "Deviceid": Deviceid,
            "DeviceType": DeviceType,    # android/ios/web
            "Timestamp": timestamp
        }
        response = self.http_timeout().request("POST", url, headers=headers, json=payload)
        error_msg = "用户登录 - 手机验证码登录"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def loginByWechat(self, email, password, bindAccount, DeviceType="web"):
        """
        用户登录 - 微信登录
        :param email: ⽤⼾邮箱
        :param password: ⽤⼾密码   base64加密
        :param token: 可选，第三⽅登录token
        :param inviteByCode: 设备类型
        :param kwargs: 其他参数如token: 可选，第三⽅登录token
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/user/login/wechat".format(base_url)
        password = password_base64(password)
        payload = {
            "email": email,
            "password": password,
            "bindAccount": bindAccount
        }
        timestamp = str(int(time.time() * 1000))
        Deviceid = "8320afd7-9c41-402c-8136-d3b6a4e6401f"
        _Authtoken = f"{timestamp}{Deviceid}{RunConfig.AUTH_KEY}"
        Authtoken = hashlib.md5(_Authtoken.encode()).hexdigest()
        headers = {
            "Authtoken": Authtoken,    # Authtoken与Timestamp需要有对应关系
            "Deviceid": Deviceid,
            "DeviceType": DeviceType,    # android/ios/web
            "Timestamp": timestamp
        }
        response = self.http_timeout().request("POST", url, headers=headers, json=payload)
        error_msg = "用户登录 - 微信登录"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def loginByGoogle(self, idToken, bindAccount, DeviceType="web"):
        """
        用户登录 - google登录
        :param idToken: google登录后的JWT
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/user/login/google".format(base_url)
        payload = {
            "idToken": idToken,
            "bindAccount": bindAccount
        }
        timestamp = str(int(time.time() * 1000))
        Deviceid = "8320afd7-9c41-402c-8136-d3b6a4e6401f"
        _Authtoken = f"{timestamp}{Deviceid}{RunConfig.AUTH_KEY}"
        Authtoken = hashlib.md5(_Authtoken.encode()).hexdigest()
        headers = {
            "Authtoken": Authtoken,    # Authtoken与Timestamp需要有对应关系
            "Deviceid": Deviceid,
            "DeviceType": DeviceType,    # android/ios/web
            "Timestamp": timestamp
        }
        response = self.http_timeout().request("POST", url, headers=headers, json=payload)
        error_msg = "用户登录 - google登录"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def loginByApple(self, email, password, bindAccount, DeviceType="web",):
        """
        用户登录 - 苹果账号登录
        :param email:
        :param password:
        :param token:
        :param inviteByCode:
        :param kwargs:
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/user/login/apple".format(base_url)
        password = password_base64(password)
        payload = {
            "email": email,
            "password": password,
            "bindAccount": bindAccount
        }
        timestamp = str(int(time.time() * 1000))
        Deviceid = "8320afd7-9c41-402c-8136-d3b6a4e6401f"
        _Authtoken = f"{timestamp}{Deviceid}{RunConfig.AUTH_KEY}"
        Authtoken = hashlib.md5(_Authtoken.encode()).hexdigest()
        headers = {
            "Authtoken": Authtoken,    # Authtoken与Timestamp需要有对应关系
            "Deviceid": Deviceid,
            "DeviceType": DeviceType,    # android/ios/web
            "Timestamp": timestamp
        }
        response = self.http_timeout().request("POST", url, headers=headers, json=payload)
        error_msg = "用户登录 - 苹果账号登录"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def get_authorization(self, position=0):
        '''根据position登录后获取对应的authorization'''
        names, emails, passwords, tokens = self.get_user_account()
        for i in range(10):
            try:
                authorization = self.login(emails[position], passwords[position], token=tokens[position])["data"]["token"]
                break
            except Exception as e:
                error_msg = e
                time.sleep(.5)
        else:
            assert False, "登录失败-->{}".format(error_msg)
        return authorization

    def get_admin_authorization(self, position=0):
        '''根据position登录后获取对应的authorization'''
        names, emails, passwords, tokens = self.get_user_account()
        for i in range(10):
            try:
                authorization = self.admin_login(emails[position], passwords[position], token=tokens[position])["data"]["token"]
                break
            except Exception as e:
                error_msg = e
                time.sleep(.5)
        else:
            assert False, "登录失败-->{}".format(error_msg)
        return authorization

    def operate_download(self, ETEAMSID, url, payload, fileName):
        '''下载docx文件文件'''

        headers = {'Cookie': 'ETEAMSID='+ETEAMSID+''}
        response = self.http_timeout().request("POST", url, headers=headers, json=payload)
        if response.status_code == 302:
            redirect_url = response.headers.get('Location')
            response = requests.get(redirect_url, headers=headers)
        assert response.status_code == 200, f"下载文件失败，url->{url}，失败信息->{response.reason}{response.json()}"
        file_path = os.getcwd() + f'/report/{fileName}.docx'
        with open(file_path, 'wb') as file:
            file.write(response.content)

    def _generate_auth_token(self, timestamp, device_id=""):
        """生成AuthToken"""
        _DeviceId = device_id if device_id else DeviceId
        key = f"{timestamp}{_DeviceId}{AUTH_KEY}"
        return hashlib.md5(key.encode()).hexdigest()

    def request_header(self, timestamp, authorization, DeviceType, **kwargs):
        """生成AuthToken"""
        Authtoken = self._generate_auth_token(timestamp)
        if authorization == 'missing':
            headers = {
                "AuthToken": Authtoken,
                "DeviceId": DeviceId,
                "DeviceType": DeviceType,    # android/ios/web
                "Timestamp": timestamp
            }
            headers.update(kwargs)
        else:
            headers = {
                "authorization": authorization,
                "AuthToken": Authtoken,
                "DeviceId": DeviceId,
                "DeviceType": DeviceType,    # android/ios/web
                "Timestamp": timestamp
            }
            headers.update(kwargs)
        return headers

    def request_body(self, payload, **kwargs):
        if kwargs.get("pop_item"):
            pop_item = kwargs.get("pop_item")
            if isinstance(pop_item, list):
                for item in pop_item:
                    payload.pop(item)
                    kwargs.pop(item)
            else:
                payload.pop(pop_item)
                kwargs.pop("pop_item")
        payload.update(kwargs)
        return payload

    def check_str_language(self, _string):  # 正则表达式判断是否为中文字符
        '''检查字符串是中文还是英文'''
        if bool(re.search('[\u4e00-\u9fff]', _string)):
            return "zh"
        elif bool(re.search('[a-zA-Z]', _string)):
            return "en"


