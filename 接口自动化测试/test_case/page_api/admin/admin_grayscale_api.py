import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
official_baseurl = BaseAPI().official_baseurl()
admin_base_url = BaseAPI().admin_baseurl()


class AdminGrayscaleApi(BaseAPI):
    """书籍接口"""

    def grayscale_batch_set(self, authorization, userKeys, DeviceType="web", code=200):
        """
        添加白名单
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{admin_base_url}/admin/grayscale/user/batch-set"
        payload = {
            "feature": "new_user_home_page",
            "userKeys": userKeys,
            "enabled": True
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "添加白名单"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if response.status_code != 401:
            response = response.json()
            return response
