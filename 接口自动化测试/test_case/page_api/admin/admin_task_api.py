import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().admin_baseurl()


class AdminTaskApi(BaseAPI):

    def calculateUserPreference(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        手动触发 T-1（昨天）的偏好分计算任务
        :param studyPlanId: (integer, path, required) studyPlanId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-10-24
        url = f"https://{base_url}/admin/user-preference/calculate"
        payload = {}
        payload = payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "手动触发 T-1（昨天）的偏好分计算任务"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def aggregateCourseCompletion(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        统计的是指定日期当天的行为偏好数据

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-22
        url = f"https://{base_url}/admin/task/aggregate-course-completion"
        payload = {
            'date': '2025-11-25'
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "统计的是指定日期当天的行为偏好数据"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def aggregateDailyBehavior(self, authorization, DeviceType="web", code=200):
        """
        手动触发指定日期的互动行为数据聚合任务

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-22
        url = f"https://{base_url}/admin/task/aggregate-daily-behavior"
        payload = {
            'date': '2025-11-25'
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "手动触发指定日期的互动行为数据聚合任务"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def knowledgeDecay(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        手动触发知识遗忘衰减任务，对最近14天内有活跃学习行为的孩子进行技能掌握度衰减计算

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-22
        url = f"https://{base_url}/admin/task/knowledge-decay"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "手动触发知识遗忘衰减任务，对最近14天内有活跃学习行为的孩子进行技能掌握度衰减计算"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

