import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminAutherRankingApi(BaseAPI):
    """admin站点作者排名接口"""

    def calculate(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        触发作者排名计算
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.20.0  &  2025-01-27
        url = f"https://{base_url}/admin/author-ranking/calculate"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "触发作者排名计算"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False
