import json
import os
import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
AUTH_KEY = RunConfig.AUTH_KEY


class AiServerApi(BaseAPI):
    """AIserver相关接口"""

    def lecture_info(self, authorization, course_id, DeviceType="web", code=200):
        """
        翻译文本
        :param targetLanguageCode: (string, query, required) 目标语言代码
        :param text: (string, query, required) 要翻译的文本
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-10-20
        url = f"https://{base_url}/api/aiserver/tutor/lecture-info/{course_id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "翻译文本"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def plan_lecture_quiz(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        翻译文本
        :param targetLanguageCode: (string, query, required) 目标语言代码
        :param text: (string, query, required) 要翻译的文本
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-10-20
        url = f"https://{base_url}/api/aiserver/tutor/plan-lecture-quiz"
        payload = {
            "lecture_id": 0,
            "skill_ids": [],
            "target_age": 5,
            "difficulty": 2,
            "language": "en",
            "learning_objectives": '',
            "assessment": '',
            "knowledge_points": ''
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "翻译文本"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False