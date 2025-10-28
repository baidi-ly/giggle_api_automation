import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
admin_base_url = BaseAPI().admin_baseurl()


class AdminBannerApi(BaseAPI):
    """扭蛋接口"""

    def getBannerList(self, authorization, location='', page=0, size=10, DeviceType="web", code=200, **kwargs):
        """
        获取Banner列表
        :param location: (string, query, optional) 广告位置
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页大小
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-28
        url = f"https://{admin_base_url}/admin/banner/list"
        payload = {
            "location": location,
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取Banner列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

