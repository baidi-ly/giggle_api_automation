
from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
DeviceId = RunConfig.DeviceId


class TagApi(BaseAPI):
    """标签接口"""