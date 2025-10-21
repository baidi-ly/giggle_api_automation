import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class Study_planApi(BaseAPI):
    """学习计划接口"""

    def study_plan_list(self, authorization, ageGroup='3-5', all=True, category='vocabulary', page=0, size=10,
                DeviceType="web", code=200, **kwargs):
        """
        学习计划包列表
        :param ageGroup: (string, query, optional) 年龄段筛选
        :param all: (boolean, query, optional) 是否获取全部
        :param category: (string, query, optional) 分类筛选
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/api/study-plan/list"
        payload = {
            "ageGroup": ageGroup,
            "all": all,
            "category": category,
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "学习计划包列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def studyPlan_details(self, authorization, studyPlanId=0, DeviceType="web", code=200, **kwargs):
        """
        学习计划包详情
        :param studyPlanId: (integer, path, required) 学习计划ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/api/study-plan/{studyPlanId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "学习计划包详情"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def study_plan_units(self, authorization, studyPlanId=0, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        学习计划单元列表
        :param studyPlanId: (integer, path, required) 学习计划ID
        :param kidId: (integer, query, optional) 孩子ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/api/study-plan/{studyPlanId}/units"
        payload = {
            "kidId": kidId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "学习计划单元列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def study_plan_contents(self, authorization, unitId=0, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        学习计划单元内容列表
        :param unitId: (integer, path, required) 单元ID
        :param kidId: (integer, query, optional) 孩子ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/api/study-plan/unit/{unitId}/contents"
        payload = {
            "kidId": kidId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "学习计划单元内容列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def study_plan_progress(self, authorization, studyPlanId=0, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        获取学习计划进度
        :param studyPlanId: (integer, path, required) 学习计划ID
        :param kidId: (integer, query, optional) 孩子ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/api/study-plan/{studyPlanId}/progress"
        payload = {
            "kidId": kidId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取学习计划进度"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def studyplan_content_complete(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        完成学习计划内容
        :param request: (object, body, optional) 完成学习计划内容请求
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/api/study-plan/content/complete"
        payload = {
            "completionTime": "2025-10-21T08:36:11.811Z",
            "kidId": 0,
            "learningDuration": 0,
            "studyPlanContentId": 0,
            "studyPlanId": 0,
            "studyPlanUnitId": 0
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "完成学习计划内容"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

