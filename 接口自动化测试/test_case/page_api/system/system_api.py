
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class SystemApi(BaseAPI):
    """书籍接口"""

    def health(self, authorization, token, DeviceType="web", code=200):
        """
        系统健康状态检查
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/api/system/health"
        payload = {
            "token": token
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "系统健康状态检查"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
            response = response.json()
            return response

    def info(self, authorization, token, DeviceType="web", code=200):
        """
        系统信息检查
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/api/system/info"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "token": token
        }

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "系统信息检查"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if code != 401:
            response = response.json()
            return response

    def ping(self, authorization, token, DeviceType="web", code=200):
        """
        简单的ping检查
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/api/system/ping"
        payload = {
            "token": token
        }

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "简单的ping检查"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if code != 401:
            response = response.json()
            return response