import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
AUTH_KEY = RunConfig.AUTH_KEY


class KidApi(BaseAPI):
    """孩子学习统计接口"""

    def getKids(self, authorization, DeviceType="web"):
        """
        获取孩子数据
        :param page:
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  修改基线，修改时间
        # updater: 接口维护人员
        # Update Details:  接口维护详情
        url = f"https://{base_url}/api/user/kids"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取孩子数据"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        assert "data" in response,  f"{error_msg}返回结果没有data数据，url->{url}，response->{response}"
        return response["data"]

