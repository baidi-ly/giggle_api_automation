import os
import time
import sys

from config import RunConfig
from utils.TimeoutHTTPAdapter import TimeoutHTTPAdapter

base_url = RunConfig.baseurl
DEFAULT_TIMEOUT = int(RunConfig.timeout) # 单位是秒
sys.path.append(os.getcwd().split("接口自动化测试")[0])

import requests
url_list = ["weapp.mulinquan.cn", "weapp.yunteams.cn", "weapp.teamsyun.com", "weapp.eteams.cn"]
class InitAPI(object):

    def __init__(self):
        self.base_url = base_url

    # http和https超时设置,默认30秒,也可传入timeout
    def http_timeout(self, timeout=DEFAULT_TIMEOUT):
        timeout = timeout or DEFAULT_TIMEOUT
        http = requests.Session()
        # 把配置复制给http和https请求
        adapter = TimeoutHTTPAdapter(timeout=timeout)
        http.mount("https://", adapter)
        http.mount("http://", adapter)
        return http

    def register(self, username, email, password, verifyCode, inviteByCode, bindAccount='', DeviceType="web"):
        """
        用户注册接口
        :param username: 用户名，3-20位字符
        :param email: 邮箱地址，必须是有效格式
        :param password: 密码，6-20位包含字⺟数字
        :param verifyCode: 验证码，6位数字
        :param inviteByCode: 邀请码，可选
        :param inviteByCode: 设备类型
        :return:
        """
        # Create Data:  ?  2025-09-05
        # Creator: Baidi
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/api/user/register".format(base_url)
        payload = {
            "username": username,
            "email": email,
            "password": password,
            "verifyCode": verifyCode,
            "inviteByCode": inviteByCode,
            'bindAccount': bindAccount
        }
        headers = {
            "DeviceId": "TEST_DEVICE_001",
            "DeviceType": DeviceType,    # android/ios/web
            "Timestamp": str(time.time() * 1000)
        }
        response = self.http_timeout().request("POST", url, headers=headers, json=payload)
        error_msg = "用户注册接口"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def api_clear_account_txt(self, file_name=RunConfig.filename):
        '''清空账号数据'''
        base_dir = os.getcwd()
        base_dir = str(base_dir).split("test_data")[0].split("test_case")[0]
        base = os.path.join(base_dir, 'test_data')
        os.chdir(base)
        f = open(file_name, 'w', encoding="UTF-8")
        f.truncate()
        f.close()

    def api_store_account_txt(self, account_list, file_name=RunConfig.filename):
        '''存储账号数据'''
        base_dir = os.getcwd()
        base_dir = str(base_dir).split("test_data")[0].split("test_case")[0]
        base = os.path.join(base_dir, 'test_data')
        os.chdir(base)
        f = open(file_name, 'w+', encoding="UTF-8")
        for account in account_list:
            f.write(account)
        f.close()

    def register_email(self, username, email, password, verifyCode, inviteByCode, bindAccount, DeviceType="web"):
        """
        用户注册接口
        :param username: 用户名，3-20位字符
        :param email: 邮箱地址，必须是有效格式
        :param password: 密码，6-20位包含字⺟数字
        :param verifyCode: 验证码，6位数字
        :param inviteByCode: 邀请码，可选
        :param inviteByCode: 设备类型
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/user/register/email".format(base_url)
        payload = {
            "username": username,
            "email": email,
            "password": password,
            "verifyCode": verifyCode,
            "inviteByCode": inviteByCode,
            "bindAccount": bindAccount
        }
        headers = {
            "DeviceId": "TEST_DEVICE_001",
            "DeviceType": DeviceType,    # android/ios/web
            "Timestamp": str(time.time() * 1000)
        }
        response = self.http_timeout().request("POST", url, headers=headers, json=payload)
        error_msg = "用户注册接口"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def register_phone(self, username, email, password, verifyCode, inviteByCode, bindAccount, DeviceType="web"):
        """
        用户注册接口
        :param username: 用户名，3-20位字符
        :param email: 邮箱地址，必须是有效格式
        :param password: 密码，6-20位包含字⺟数字
        :param verifyCode: 验证码，6位数字
        :param inviteByCode: 邀请码，可选
        :param inviteByCode: 设备类型
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/user/register/phone".format(base_url)
        payload = {
            "username": username,
            "email": email,
            "password": password,
            "verifyCode": verifyCode,
            "inviteByCode": inviteByCode,
            "bindAccount": bindAccount
        }
        headers = {
            "DeviceId": "TEST_DEVICE_001",
            "DeviceType": DeviceType,    # android/ios/web
            "Timestamp": str(time.time() * 1000)
        }
        response = self.http_timeout().request("POST", url, headers=headers, json=payload)
        error_msg = "用户注册接口"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response