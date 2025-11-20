import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class QuizApi(BaseAPI):
    """quiz接口"""

    def quizId_detail(self, authorization, quizId=0, DeviceType="web", code=200, **kwargs):
        """
        查询指定quiz的详情
        :param quizId: (integer, path, required) 测验ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-04
        url = f"https://{base_url}/api/quiz/{quizId}/detail"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询指定quiz的详情"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def promotion_submit(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        提交晋级Quiz（批量提交并完成）
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-11
        url = f"https://{base_url}/api/quiz/promotion/submit"
        payload = {
            "kidId": 123,
            "questions": [
                {
                    "questionSeqNo": 1,
                    "questionId": 456,
                    "questionContent": "What is 1+1?",
                    "correctAnswer": "2",
                    "userAnswer": "2",
                    "isCorrect": True,
                    "skillTags": ["Math", "Addition"],
                    "questionLevel": "Level1",
                    "completeTime": "2024-11-05T10:00:00"
                }
            ],
            "targetLevel": "Level2",
            "educationType": "ESL"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "提交晋级Quiz（批量提交并完成）"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def submit_lesson_quiz(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        提交课后quiz
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-15
        url = f"https://{base_url}/api/quiz/lesson/submit"
        payload = {
            "kidId": 0,
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
                    "skillTags": [
                        "string"
                    ],
                "completeTimeStamp": 0
                }
            ]
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "提交课后quiz"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def fetchQuestions(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        根据题库获取Quiz题目
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-19
        url = f"https://{base_url}/api/quiz/fetch-questions"
        payload = {
            "count": 0,
            "kidId": 0,
            "quizType": "PLACEMENT"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "根据题库获取Quiz题目"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def placementSubmit(self, authorization, kidId, placementLevel, questions=[], DeviceType="web", code=200, **kwargs):
        """
        提交定级Quiz
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-19
        url = f"https://{base_url}/api/quiz/placement/submit"
        payload = {
            "kidId": kidId,
            "placementLevel": placementLevel,
            "completeTimeStamp": 0,
            "questions": questions
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "提交定级Quiz"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def lessonSubmit(self, authorization, kidId, courseId, questions=[], DeviceType="web", code=200, **kwargs):
        """
        提交课后Quiz
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-19
        url = f"https://{base_url}/api/quiz/lesson/submit"
        payload = {
            "kidId": kidId,
            "courseId": courseId,
            "completeTimeStamp": 0,
            "questions": questions
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "提交课后Quiz"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def promotionPubmit(self, authorization, request='', DeviceType="web", code=200, **kwargs):
        """
        提交晋级Quiz
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-19
        url = f"https://{base_url}/api/quiz/promotion/submit"
        payload = {
            "request": request
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "提交晋级Quiz"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

