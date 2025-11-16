import json
import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
DeviceId = RunConfig.DeviceId


class TagApi(BaseAPI):
    """标签接口"""

    def popular_tags(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取当前被引用的最多的12个标签

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-15
        url = f"https://{base_url}/api/tag/popular"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取当前被引用的最多的12个标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

