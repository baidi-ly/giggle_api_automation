
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class VertifyApi(BaseAPI):
    """书籍接口"""

    def submitToBot(self, authorization, DeviceType="web"):
        """
        批量提交书籍到AI-Bot审核
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/verify/submitToBot"
        payload = {}

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers)
        error_msg = "批量提交书籍到AI-Bot审核"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response
