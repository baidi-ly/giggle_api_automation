import json
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

    def recommendation(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取课程推荐
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-24
        url = f"https://{base_url}/api/course/recommendation"
        payload = {
            "currentCourseId": 123456,
            "includeReasonInfo": False,
            "kidId": "kid123",
            "recommendCount": 2
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "获取课程推荐"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getTags(self, authorization, page=0, size=20, DeviceType="web", code=200, **kwargs):
        """
        查询所有推荐和热门标签
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-10
        url = f"https://{base_url}/api/course/tags"
        payload = {
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询所有推荐和热门标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def course_albums(self, authorization, page=0, size=20, DeviceType="web", code=200, **kwargs):
        """
        查询所有生效中的专辑及其标签
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-11
        url = f"https://{base_url}/api/course/albums"
        payload = {
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询所有生效中的专辑及其标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def promotion_check(self, authorization, kidId=0, DeviceType="web", code=200):
        """
        查询晋级资格
        :param kidId: (integer, query, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-17
        url = f"https://{base_url}/api/course/promotion/check"
        payload = {
            "kidId": kidId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询晋级资格"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def course_recommends(self, authorization, kidId, learningLevel='L1', DeviceType="web", code=200):
        """
        获取课程推荐列表（需要认证）
        :param kidId: (integer, query, required) 孩子ID
        :param learningLevel: (string, query, required) 学习等级（可选），如L1、L2等
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-17
        url = f"https://{base_url}/api/course/recommend/list"
        payload = {
            "kidId": kidId,
            "learningLevel": learningLevel
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取课程推荐列表（需要认证）"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def course_public_recommends(self, authorization, learningLevel='L1', DeviceType="web", code=200, **kwargs):
        """
        获取课程推荐列表（公开接口）
        :param learningLevel: (string, query, required) 学习等级，如L1、L2等
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-17
        url = f"https://{base_url}/api/course/recommend/public/list"
        payload = {
            "learningLevel": learningLevel
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取课程推荐列表（公开接口）"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getTagBaseRecommend(self, authorization, kidId, learningLevel='l1', size=10, strategy='BasicFiltering',
                            DeviceType="web", code=200):
        """
        获取推荐课程列表
        :param kidId: (integer, query, optional) 孩子ID，注册用户必填
        :param learningLevel: (string, query, optional) 学习等级，访客模式必填
        :param size: (integer, query, optional) 返回数量，最大50
        :param strategy: (string, query, optional) 推荐策略，当前仅支持BasicFiltering
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-17
        url = f"https://{base_url}/api/course/tag-base-recommend"
        payload = {
            "kidId": kidId,
            "learningLevel": learningLevel,
            "size": size,
            "strategy": strategy
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取推荐课程列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def coursesByTag(self, authorization, tagId, page=0, size=20, DeviceType="web", code=200):
        """
        根据标签ID查询对应的课程列表
        :param tagId: (integer, path, required) 标签ID
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-17
        url = f"https://{base_url}/api/course/tags/{tagId}/courses"
        payload = {
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据标签ID查询对应的课程列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

