import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().admin_baseurl()


class AdminActivityApi(BaseAPI):
    """活动接口"""

    def getList(self, authorization, all=False, keyword='', page=0, size=10, status='', DeviceType="web", code=200, **kwargs):
        """
        获取活动列表
        :param all: (boolean, query, optional) all
        :param keyword: (string, query, optional) keyword
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :param status: (string, query, optional) status
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/admin/activity/list"
        payload = {
            "all": all,
            "keyword": keyword,
            "page": page,
            "size": size,
            "status": status
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取活动列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def activity_create(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        创建活动
        :param name: (string, body, required) name 参数
        :param activityCode: (string, body, required) activityCode 参数
        :param startTime: (string, body, required) startTime 参数
        :param endTime: (string, body, required) endTime 参数
        :param config: (object, body, required) config 参数
        :param status: (string, body, required) status 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/admin/activity/create"
        payload = {
            "name": "扭蛋抽奖活动",
            "activityCode": "GACHA_2024",
            "startTime": "",
            "endTime": "",
            "status": "ACTIVE"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建活动"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def activity_tags(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取标签列表

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-06
        url = f"https://{base_url}/admin/activity/tag/list"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取标签列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def activity_general_tasks(self, authorization, DeviceType="web", code=200):
        """
        获取通用活动任务定义列表

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-06
        url = f"https://{base_url}/admin/activity/task/general/list"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取通用活动任务定义列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def create_activity_task(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        创建活动任务定义
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-06
        url = f"https://{base_url}/admin/activity/task"
        payload = {
            "activityId": 1,
            "actionCode": "SHARE",
            "name": "分享任务"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建活动任务定义"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def delete_activity_task(self, authorization, id=0, DeviceType="web", code=200):
        """
        删除活动任务定义
        :param id: (integer, path, required) id
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-06
        url = f"https://{base_url}/admin/activity/task/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除活动任务定义"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def delete_activity(self, authorization, activityId=0, DeviceType="web", code=200, **kwargs):
        """
        获取活动详情
        :param activityId: (integer, path, required) activityId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-06
        url = f"https://{base_url}/admin/activity/{activityId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "获取活动详情"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updateActivityStatus(self, authorization, activity_id, status='ACTIVE', DeviceType="web", code=200):
        """
        更新活动状态
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-02
        url = f"https://{base_url}/admin/activity/status"
        payload = {
            "id": activity_id,
            "status": status
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新活动状态"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

