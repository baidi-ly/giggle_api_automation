
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class UserApi(BaseAPI):
    """书籍接口"""

    def get_videoWhitelist(self, authorization, DeviceType="web"):
        """
        获取视频白名单用户列表
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/user/videoWhitelist"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取视频白名单用户列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_videoWhitelist(self, authorization, userIds:[], DeviceType="web"):
        """
        视频白名单用户全量更新
        :param userIds: 更新后的用户列表
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/user/videoWhitelist/"
        payload = {
            "userIds": userIds
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "视频白名单用户全量更新"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def bindWechat(self, authorization, DeviceType="web"):
        """
        绑定微信账号
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/user/bindWechat"
        timestamp = str(int(time.time() * 1000))
        payload = {}

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "绑定微信账号"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def unbindWechat(self, authorization, DeviceType="web"):
        """
        解绑微信账号
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/user/unbindWechat"
        timestamp = str(int(time.time() * 1000))
        payload = {}

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "解绑微信账号"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def bindApple(self, authorization, DeviceType="web"):
        """
        绑定Apple账号
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/user/bindApple"
        timestamp = str(int(time.time() * 1000))
        payload = {}

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "绑定Apple账号"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def unbindApple(self, authorization, DeviceType="web"):
        """
        解绑Apple账号
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/user/unbindApple"
        payload = {}

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "解绑Apple账号"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def profile(self, authorization, bindAccount, DeviceType="web"):
        """
        用户注册接口
        :param bindAccount: 用户名，3-20位字符
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/user/profile".format(base_url)
        payload = {
            "bindAccount": bindAccount
        }

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "解绑Apple账号"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def refresh(self, authorization, bindAccount, DeviceType="web"):
        """
        用户注册接口
        :param bindAccount: 用户名，3-20位字符
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/user/refresh".format(base_url)
        payload = {
            "bindAccount": bindAccount
        }

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "解绑Apple账号"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response
