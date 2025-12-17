
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class PosterApi(BaseAPI):
    """海报接口"""

    def poster_list(self, authorization,  DeviceType="web"):
        """
        上传通用资源文件
        :param:
        :return:
        """
        # Create Data:  ?  2025-09-11
        # Creator: Baidi
        url = f"https://{base_url}/api/poster/list"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "上传通用资源文件"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def generate_poster(self, authorization, posterId, DeviceType="web", **kwargs):
        """
        上传通用资源文件
        :param:
        :return:
        """
        # Create Data:  ?  2025-09-08
        # Creator: Baidi
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增参数: `direction`, `scale`
        url = f"https://{base_url}/api/poster/generate"
        payload = {
            "posterId": posterId,
            "bind": {
                "name": "Test User",
                "score": 100
            },
            "posterFileType": "url",
            "language": "en"
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "上传通用资源文件"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def poster_list(self, authorization, DeviceType="web"):
        """
        获取所有启用的海报模板列表
        Returns:
            海报模板列表
        """
        url = f"https://{base_url}/api/poster/list"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取所有启用的海报模板列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getPosterById(self, authorization, poster_id, DeviceType="web"):
        """
        根据ID获取海报模板详情
        Args:
            poster_id: 海报模板ID
        Returns:
            海报模板详情
        """
        url = f"https://{base_url}/api/poster/{poster_id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "根据ID获取海报模板详情"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response
