import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminStudyplanApi(BaseAPI):

    pass

    def study_plan_create(self, authorization, contents=[], DeviceType="web", code=200, **kwargs):
        """
        创建学习计划（包含单元和内容）
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/admin/study-plan/create"
        payload = {
            "name": "基础词汇学习计划",
            "imageKey": "study-plan-001.jpg",
            "category": "vocabulary",
            "ageGroup": "3-5",
            "goal": "掌握100个基础单词",
            "gigglesReward": 50,
            "units": [
                {
                    "name": "第一单元：基础单词",
                    "sortOrder": 1,
                    "contents": contents
                }
            ]
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建学习计划（包含单元和内容）"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def putStatus(self, authorization, studyPlanId=0, status=1, DeviceType="web", code=200, **kwargs):
        """
        学习计划状态变更
        :param studyPlanId: (integer, path, required) studyPlanId
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/admin/study-plan/{studyPlanId}/status"
        payload = {
          "status": status
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "学习计划状态变更"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

