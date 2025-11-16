import json
import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
AUTH_KEY = RunConfig.AUTH_KEY


class KidApi(BaseAPI):
    """孩子学习统计接口"""

    def getKids(self, authorization, DeviceType="web"):
        """
        获取孩子数据
        :param page:
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  修改基线，修改时间
        # updater: 接口维护人员
        # Update Details:  接口维护详情
        url = f"https://{base_url}/api/user/kids"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取孩子数据"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        assert "data" in response,  f"{error_msg}返回结果没有data数据，url->{url}，response->{response}"
        return response

    def check_placement(self, authorization, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        查询是否需要定级
        :param kidId: (integer, query, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-15
        url = f"https://{base_url}/api/kid/placement/check"
        payload = {
            "kidId": kidId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询是否需要定级"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getLearningProgress(self, authorization, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        查询晋级进度条
        :param kidId: (integer, path, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-15
        url = f"https://{base_url}/api/kid/{kidId}/learning-progress"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询晋级进度条"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def learningLevel(self, authorization, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        访客模式数据同步或注册用户定级数据保存
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-15
        url = f"https://{base_url}/api/kid/learning-level"
        payload = {
            "kidId": kidId,
            "placementLevel": "string",
            "placementQuestionRecords": {
                "completeTimeStamp": 0,
                "questions": [
                    {
                        "quizId": "string",
                        "questionId": 0,
                        "questionSeqNo": 0,
                        "question": "string",
                        "userAnswer": "string",
                        "correctAnswer": "string",
                        "isCorrect": True,
                        "skillTags": ["string"],
                        "completeTimeStamp": 0
                        }
                    ]
                },
                "lessonQuestionRecords": [
                    {
                        "courseId": 0,
                        "completeTimeStamp": 0,
                        "questions": [
                            {
                                "quizId": "string",
                                "questionId": 0,
                                "questionSeqNo": 0,
                                "question": "string",
                                "userAnswer": "string",
                                "correctAnswer": "string",
                                "isCorrect": True,
                                "skillTags": ["string"],
                                "completeTimeStamp": 0
                            }
                        ]
                    }
                ],
            "lessonComplete": [0]
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "访客模式数据同步或注册用户定级数据保存"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

