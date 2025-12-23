import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
admin_base_url = BaseAPI().admin_baseurl()


class AdminStatisticsApi(BaseAPI):
    '''游客统计数据 api'''

    def getGuestRetention(self, authorization, DeviceType="web"):
        """
        获取游客留存统计数据

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/admin/statistics/guest-retention"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取游客留存统计数据"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response
