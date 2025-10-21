import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminTabstorybookApi(BaseAPI):
    """admin站点故事书Tab接口"""

    def visible(self, authorization, visible, DeviceType="web", code=200, **kwargs):
        """
        设置故事书Tab显示状态
        :param visible: (boolean, query, required) 是否显示故事书Tab
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.20.0  &  2025-01-27
        url = f"https://{base_url}/admin/tab-storybook/visible"
        payload = {
            "visible": visible
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "设置故事书Tab显示状态"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False
