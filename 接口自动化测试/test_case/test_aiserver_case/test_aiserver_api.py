from time import strftime

import pytest


from config import RunConfig
from test_case.page_api.aiserver.aiserver_api import AiServerApi

base_url = RunConfig.baseurl

class TestAiServerApi:
    """
    ai 接口测试用例
    """

    def setup_class(self):
        self.ai_server = AiServerApi()
        self.authorization = self.ai_server.get_authorization()[0]
        self.now = strftime("%Y%m%d%H%M%S")