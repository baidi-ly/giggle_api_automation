import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminCastApi(BaseAPI):
    """后台博客接口"""

    def getAlbums(self, authorization, languageCode='', DeviceType="web", code=200, **kwargs):
        """
        查询播客的专辑
        :param languageCode: (string, query, optional) 语言编码
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-05
        url = f"https://{base_url}/admin/cast/albums"
        payload = {
            "languageCode": languageCode
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询播客的专辑"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

