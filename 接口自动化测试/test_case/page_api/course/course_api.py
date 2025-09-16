
import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
DeviceId = RunConfig.DeviceId


class CourseApi(BaseAPI):
    """书籍接口"""

    def listAllWithLevel(self, authorization, DeviceType="web"):
        """
        获取所有课程，并按级别分组（分批循环查询全部数据，每批次500条）
        :param:
        :return:
        """
        # Create Data:
        # Creator: Baidi
        url = f"https://{base_url}/api/course/listAllWithLevel"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取所有课程，并按级别分组（分批循环查询全部数据，每批次500条）"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def blockedCourseIds(self, authorization='', DeviceType="web", code=200):
        """
        获取屏蔽的课程ID列表
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/api/course/blockedCourseIds"
        timestamp = str(int(time.time() * 1000))
        Authtoken = self._generate_auth_token(timestamp)
        headers = {
            "AuthToken": Authtoken,
            "DeviceId": DeviceId,
            "DeviceType": DeviceType,    # android/ios/web
            "Timestamp": timestamp
        }
        if authorization:
            headers.update(authorization=authorization)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取屏蔽的课程ID列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getDetail(self, authorization, DeviceType="web", **kwargs):
        """
        获取课程详情包括版本信息
        :param page:
        :return:
        """
        # Create Data:  自动生成 2025-09-15
        # Creator: Swagger Generator
        # Update Date:
        # updater:
        # Update Details:
        url = f"https://{base_url}/api/course/content/detail"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=kwargs)
        error_msg = "获取课程详情包括版本信息"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        assert "data" in response,  f"{error_msg}返回结果没有data数据，url->{url}，response->{response}"
        return response["data"]

    def getListallwithlevel(self, authorization, DeviceType="web", **kwargs):
        """
        获取所有课程，并按级别分组（分批循环查询全部数据，每批次500条）
        :param page:
        :return:
        """
        # Create Data:  V1.19.0  &  2025-09-16
        url = f"https://{base_url}/api/course/listAllWithLevel"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("get", url, headers=headers, params=kwargs)
        error_msg = "获取所有课程，并按级别分组（分批循环查询全部数据，每批次500条）"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        assert "data" in response,  f"{error_msg}返回结果没有data数据，url->{url}，response->{response}"
        return response["data"]

