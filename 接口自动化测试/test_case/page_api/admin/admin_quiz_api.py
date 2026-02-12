import json
import time

from test_case.page_api.admin.admin_course_api import admin_base_url
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
admin_base_url = BaseAPI().admin_baseurl()


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
            "name": "基础词汇测验",
            "quizType": "LESSON",
            "targetAge": 5,
            "difficulty": 1,
            "questionCount": 10,
            "language": "en",
            "preferenceKey": None,
            "courseContent": []
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
        获取quiz列表
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
        error_msg = "获取quiz列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def generate_question(self, authorization, courseId, questionPlan=[], referenceImageKey='',
                          preferenceKey='preferences/level_L1', DeviceType="web", code=200):
        """
        AI生成题目 - 提交生成任务
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-20
        url = f"https://{admin_base_url}/admin/quiz/question/generate"
        payload = {
            "coursePlans": [
                {
                    "courseId": courseId,
                    "questionPlan": questionPlan,
                    "referenceImageKey": referenceImageKey
                }
            ],
            "preferenceKey": preferenceKey
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "AI生成题目 - 提交生成任务"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def quiz_questions(self, authorization, DeviceType="web", **kwargs):
        """
        题库列表查询（分页）
        :param courseName: (string, query, optional) courseName
        :param description: (string, query, optional) description
        :param difficulty: (string, query, optional) difficulty
        :param page: (integer, query, optional) page
        :param questionType: (string, query, optional) questionType
        :param size: (integer, query, optional) size
        :param status: (integer, query, optional) status
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-20
        url = f"https://{admin_base_url}/admin/quiz/question/list"
        payload = {
            "courseName": '',
            "page": 0,
            "size": 1000,
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "题库列表查询（分页）"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def quiz_question_status(self, authorization, questionId, status=0, DeviceType="web", code=200):
        """
        启用/禁用题目
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-20
        url = f"https://{admin_base_url}/admin/quiz/question/status"
        payload = {
            "id": questionId,
            "status": status
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "启用/禁用题目"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def delete_quiz_question(self, authorization, questionId=0, DeviceType="web", code=200):
        """
        删除题目
        :param questionId: (integer, path, required) questionId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-20
        url = f"https://{admin_base_url}/admin/quiz/question/{questionId}/delete"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除题目"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def questionDifficultyFix(self, authorization, DeviceType="web", code=200):
        """
        题目difficulty修正

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-24
        url = f"https://{admin_base_url}/admin/quiz/question/difficulty/fix"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "题目difficulty修正"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def create_question(self, authorization, courseId, questionType, questionDescription,
                              skill, difficulty, questionContent, index=0, status=1, DeviceType="web"):
        '''添加题目'''
        url = f"https://{base_url}/admin/quiz/question/create"
        payload = {
            "courseId": courseId,
            "questionType": questionType,
            "questionDescription": questionDescription,
            "skill": skill,
            "difficulty": difficulty,
            "questionContent": questionContent,
            "index": index,
            "status": status
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "添加题目"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        return response.json()

    def delete_question(self, authorization, questionId, DeviceType="web"):
        """
        删除题目
        """
        url = f"https://{base_url}/admin/quiz/question/{questionId}/delete"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除题目"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        return response.json()

    def generate_tts(self, authorization, question_ids, DeviceType="web"):
        """
        批量生成题目TTS：POST /quiz/question/tts/generate
        body: {"questionIds": [1,2,3]}
        """
        url = f"https://{base_url}/admin/quiz/question/tts/generate"
        payload = {"questionIds": question_ids}
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "批量生成题目TTS"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        return response.json()

    def get_tts_status(self, authorization, DeviceType="web"):
        """
        获取TTS队列状态：GET /quiz/question/tts/status
        返回示例 data: { "queueSize": 3 }
        """
        url = f"https://{base_url}/admin/quiz/question/tts/status"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取TTS队列状态"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        return response.json()