import pytest
import time

from test_case.page_api.email.email_api import EmailApi
from config import RunConfig

base_url = RunConfig.baseurl

class TestEmailApi:
    """
    邮件接口测试用例
    """

    def setup_class(self):
        self.email = EmailApi()
        self.authorization = self.email.get_authorization()