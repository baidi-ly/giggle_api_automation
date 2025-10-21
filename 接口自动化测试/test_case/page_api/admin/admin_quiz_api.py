import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminQuizApi(BaseAPI):

    def quiz_generate(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        生成测验
        :param quizReq: (object, body, required) quizReq
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-20
        url = f"https://{base_url}/admin/quiz/generate"
        payload = {
            "courseContent": [
            0
            ],
            "difficulty": 0,
            "language": "zh",
            "name": "string",
            "preferenceKey": "3333",
            "questionCount": 0,
            "quizType": "LESSON",
            "targetAge": 0
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "生成测验"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def quiz_list(self, authorization, keyword='', page=0, quizType='', size=10, DeviceType="web", code=200, **kwargs):
        """
        获取测验列表
        :param keyword: (string, query, optional) keyword
        :param page: (integer, query, optional) page
        :param quizType: (string, query, optional) quizType
        :param size: (integer, query, optional) size
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-20
        url = f"https://{base_url}/admin/quiz/list"
        payload = {
            "keyword": keyword,
            "page": page,
            "quizType": quizType,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取测验列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

