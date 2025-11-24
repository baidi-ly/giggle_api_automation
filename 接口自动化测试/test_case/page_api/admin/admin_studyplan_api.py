import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().admin_baseurl()


class AdminStudyplanApi(BaseAPI):

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

    def studyPlan_details(self, authorization, studyPlanId=0, DeviceType="web", code=200, **kwargs):
        """
        获取学习计划详情
        :param studyPlanId: (integer, path, required) studyPlanId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-24
        url = f"https://{base_url}/admin/study-plan/{studyPlanId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取学习计划详情"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def delete_studyPlan(self, authorization, studyPlanId=0, DeviceType="web", code=200, **kwargs):
        """
        删除学习计划包
        :param studyPlanId: (integer, path, required) studyPlanId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-24
        url = f"https://{base_url}/admin/study-plan/{studyPlanId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除学习计划包"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def update_study_plan(self, authorization, studyPlanId=0, DeviceType="web", code=200, **kwargs):
        """
        更新学习计划
        :param studyPlanId: (integer, path, required) studyPlanId
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-30
        url = f"https://{base_url}/admin/study-plan/{studyPlanId}/update"
        payload = {
            "name": "string",
            "imageKey": "string",
            "category": "string",
            "ageGroup": "string",
            "goal": "string",
            "gigglesReward": 0,
            "units": [
            {
                "name": "string",
                "sortOrder": 0,
                "contents": [
                    {
                        "name": "string",
                        "contentType": "string",
                        "difficulty": "string",
                        "wordCount": 0,
                        "contentId": 0,
                        "contentConfig": {},
                        "sortOrder": 0
                        }
                    ]
                }
            ]
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新学习计划"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def study_plan_list(self, authorization, category='', keyword='', page=0, size=20, status=0, DeviceType="web", code=200, **kwargs):
        """
        学习计划列表
        :param category: (string, query, optional) 分类筛选
        :param keyword: (string, query, optional) 关键词搜索（名称）
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :param status: (integer, query, optional) 状态筛选 (0-禁用, 1-启用)
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-30
        url = f"https://{base_url}/admin/study-plan/list"
        payload = {
            "category": category,
            "keyword": keyword,
            "page": page,
            "size": size,
            "status": status
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "学习计划列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def putStatus(self, authorization, studyPlanId=0, status=0, DeviceType="web", code=200, **kwargs):
        """
        学习计划状态变更
        :param studyPlanId: (integer, path, required) studyPlanId
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-30
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

