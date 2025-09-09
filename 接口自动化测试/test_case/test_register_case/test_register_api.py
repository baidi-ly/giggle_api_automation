import os
import unittest
import sys
import random
from time import strftime
import time
import configparser
import pytest
import string

from config import RunConfig
from test_case.page_api.base_api import BaseAPI
from test_case.page_api.init.init_api import InitAPI

sys.path.append(os.getcwd())
sys.path.append("..")

conf_file = configparser.ConfigParser()
path = os.getcwd().split('test_case')[0]

@pytest.mark.initUser
class TestRegister:

    def setup_class(self):
        self.init_api = InitAPI()
        self.base = BaseAPI()
        self.tester = RunConfig.filename
        self.now = strftime("%Y%m%d%H%M%S")


    def tear_down(self):
        pass

    def init_data(self,num):
        '''初始化数据,N位随机字符串'''
        ran = string.capwords(''.join(random.sample(string.ascii_lowercase, num)))
        return ran

    @pytest.mark.basic
    def test_init_user(self):
        '''
        注册账号，创建团队，邀请人员
        用例设计思路，各种参数化的：
        注册后各个端登录是否正常
        注册后是否能正常的注销
        注销账户后账户是否能正常使用
        '''
        username = "baidi"
        email = "bd22434@163.com"
        password = "bb22434"
        verifyCode = "123456"
        inviteByCode = ""
        sign_up_res = self.init_api.register(username, email, password, verifyCode, inviteByCode)
        assert sign_up_res["message"] == "注册成功"

        user_list = []
        self.base.get_authorization()
        user_list.append(username + "," + email + "," + password + "," + "管理员账号" + "," + str(2) + "\n")
        # 清空文件
        self.init_api.api_clear_account_txt(file_name=self.tester)
        time.sleep(1.5)
        # 所有账号写入 account.txt
        self.init_api.api_store_account_txt(user_list, self.tester)
        time.sleep(12)

        #初始化成功后修改修改构建状态
        os.chdir(path)
        RunConfig.is_build_status = True

