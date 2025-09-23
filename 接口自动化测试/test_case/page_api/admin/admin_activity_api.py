
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminActivityApi(BaseAPI):
    """活动接口"""

    def task(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        创建活动任务定义

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-23
        url = f"https://{base_url}/admin/activity/task"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "创建活动任务定义"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

