import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminTabstorybookApi(BaseAPI):
    """admin站点书籍翻译接口"""
