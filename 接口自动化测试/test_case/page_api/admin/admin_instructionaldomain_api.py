import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminInstructionaldomainApi(BaseAPI):
    """admin站点教学维度接口"""

    def createInstructionalDomain(self, authorization, name='', DeviceType="web", code=200):
        """
        创建教学维度标签
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/admin/instructional-domain/create"
        payload = {
            "name": name
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建教学维度标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def instructional_domain_getList(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取所有教学维度标签

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/admin/instructional-domain/list"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取所有教学维度标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

