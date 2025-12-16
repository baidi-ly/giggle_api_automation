import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().admin_baseurl()


class AdminFlashcardsApi(BaseAPI):

    def flashcards_create(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        新增闪卡
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/admin/flashcards/create"
        payload = {
            "name": "基础词汇闪卡",
            "description": "适合3-5岁儿童的基础单词学习",
            "coverKey": "flash_cards-cover-001.jpg",
            "words": [
                {
                    "name": "apple",
                    "lexileLevel": 100,
                    "antonym": None
                },
                {
                    "name": "banana",
                    "lexileLevel": 100,
                    "antonym": None
                },
                {
                    "name": "cat",
                    "lexileLevel": 100,
                    "antonym": None
                }
            ],
            "generateImage": True
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "新增闪卡"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def delete_flashcards(self, authorization, id, DeviceType="web", code=200):
        """
        删除闪卡
        :param request:
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/admin/flashcards/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除闪卡"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def flashcards_list(self, authorization, DeviceType="web", **kwargs):
        """
        获取闪卡列表
        :param keyword: (string, query, optional) keyword
        :param page: (integer, query, optional) page
        :param size: (integer, query, optional) size
        :param type: (string, query, optional) type
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-16
        url = f"https://{base_url}/admin/flashcards/list"
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
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response
