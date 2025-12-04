import json
import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
DeviceId = RunConfig.DeviceId


class Flash_cardsApi(BaseAPI):
    """闪卡接口"""

    def flash_cards_list(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取闪卡列表
        :param keyword: (string, query, optional) keyword
        :param page: (integer, query, optional) page
        :param size: (integer, query, optional) size
        :param type: (string, query, optional) type
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-04
        url = f"https://{base_url}/api/flash-cards/list"
        payload = {
            "keyword": '',
            "page": 0,
            "size": 10,
            "type": ''
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取闪卡列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def flash_cards_words(self, authorization, DeviceType="web", code=200):
        """
        flashCard为 NORMAL 和 NULL 的闪卡单词数量

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-04
        url = f"https://{base_url}/api/flash-cards/words/count"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "flashCard为 NORMAL 和 NULL 的闪卡单词数量"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

