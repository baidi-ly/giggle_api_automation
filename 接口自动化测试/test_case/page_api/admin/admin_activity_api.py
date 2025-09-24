
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


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

