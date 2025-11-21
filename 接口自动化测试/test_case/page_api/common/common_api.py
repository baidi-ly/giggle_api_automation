import json
import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
DeviceId = RunConfig.DeviceId


class CommonApi(BaseAPI):
    """公共接口"""

    def Getfileurl(self, authorization, key_url='', DeviceType="web", code=200):
        """
        根据url获取文件的下载链接
        :param url: (string, query, required) url
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-14
        url = f"https://{base_url}/api/common/getFileUrl"
        payload = {
            "url": key_url
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据url获取文件的下载链接"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

