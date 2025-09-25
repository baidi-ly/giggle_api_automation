
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class SchoolApi(BaseAPI):
    """学校系统接口"""


