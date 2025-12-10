import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().admin_baseurl()


class AdminIpApi(BaseAPI):
    """IP相关接口"""

    def unbanIP(self, authorization, ipAddress, DeviceType="web"):
        """
        解封IP
        :param ipAddress: 要解封的ipAddress
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/ip/unban"
        payload = {
            "ipAddress": ipAddress
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "解封IP"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def ipBannedList(self, authorization, DeviceType="web"):
        """
        查询封禁IP列表
        :return: 封禁IP列表
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/ip/banned-list"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询封禁IP列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def banIP(self, authorization, ipAddress, DeviceType="web"):
        """
        封禁IP
        :param ipAddress: 要封禁的ipAddress
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/ip/ban"
        payload = {
            "ipAddress": ipAddress
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "封禁IP"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def banCountry(self, authorization, countryCode, DeviceType="web"):
        """
        封禁的国家区号
        :param countryCode: 要封禁的国家区号，支持带或不带 “+”，会自动去掉前缀和空白后存储。
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/country-code/ban"
        payload = {
            "countryCode": countryCode
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "封禁的国家区号"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def unbanCountry(self, authorization, countryCode, DeviceType="web"):
        """
        解封的国家区号
        :param countryCode: 要封禁的国家区号，支持带或不带 “+”，会自动去掉前缀和空白后存储。
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/country-code/unban"
        payload = {
            "countryCode": countryCode
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "解封的国家区号"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def countryBannedList(self, authorization, DeviceType="web"):
        """
        查询封禁国家区号列表
        :return: 封禁国家区号列表
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/country-code/banned-list"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询封禁国家区号列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response