import json
import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
AUTH_KEY = RunConfig.AUTH_KEY


class ActivityApi(BaseAPI):
    """孩子学习统计接口"""

    def getInfo(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取扭蛋当前活动信息

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/activity/gacha/info"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取扭蛋当前活动信息"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if response.status_code != 401:
            response = response.json()
            return response

    def userGachaInfo(self, authorization, activityId=720712510713925, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        获取用户抽奖信息
        :param activityId: (integer, query, required) activityId
        :param kidId: (integer, query, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/activity/gacha/user/info"
        payload = {
            "activityId": activityId,
            "kidId": kidId
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取用户抽奖信息"
        if code != 401:
            assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
            response = response.json()
            return response

    def share(self, authorization, activityId=720712510713925, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        分享成功，增加抽奖次数
        :param activityId: (integer, query, required) activityId
        :param kidId: (integer, query, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/activity/gacha/share"
        payload = {
            "activityId": activityId,
            "kidId": kidId
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "分享成功，增加抽奖次数"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if response.status_code != 401:
            response = response.json()
            return response

    def draw(self, authorization, activityId=720712510713925, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        抽奖
        :param activityId: (integer, query, required) activityId
        :param kidId: (integer, query, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-24
        url = f"https://{base_url}/api/activity/gacha/draw"
        payload = {
            "activityId": activityId,
            "kidId": kidId
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "抽奖"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if response.status_code != 401:
            response = response.json()
            return response

    def getRewardcenter(self, authorization, activityId=0, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        扭蛋奖励中心
        :param activityId: (integer, query, required) activityId
        :param kidId: (integer, query, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-04
        url = f"https://{base_url}/api/activity/gacha/rewardCenter"
        payload = {
            "activityId": activityId,
            "kidId": kidId
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "扭蛋奖励中心"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getList(self, authorization, language='en', DeviceType="web", code=200, **kwargs):
        """
        获取当前正在进行的扭蛋活动
        :param language: (string, query, optional) language
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-14
        url = f"https://{base_url}/api/activity/gacha/list"
        payload = {
            "language": language
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取当前正在进行的扭蛋活动"
        # assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getCoursecompleteactivityid(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取完课活动ID

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-28
        url = f"https://{base_url}/api/activity/config/courseCompleteActivityId"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取完课活动ID"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def coursecompleteactivityid(self, authorization, activityId=0, DeviceType="web", code=200, **kwargs):
        """
        配置完课活动ID
        :param activityId: (integer, query, required) activityId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-28
        url = f"https://{base_url}/api/activity/config/courseCompleteActivityId"
        payload = {
            "activityId": activityId
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "配置完课活动ID"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def dailyLessonComplete(self, authorization, courseIds, kidId, DeviceType="web", code=200):
        """
        根据每日学习计划课程完成增加抽奖次数
        :param courseIds: (array, query, required) courseIds
        :param kidId: (integer, query, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-02
        url = f"https://{base_url}/api/activity/gacha/daily-lesson-complete"
        payload = {
            "courseIds": courseIds,
            "kidId": kidId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "根据每日学习计划课程完成增加抽奖次数"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def dailyLessonCompleteCheck(self, authorization, kidId, DeviceType="web", code=200):
        """
        检查今天是否已经通过每日课程完成增加过抽奖次数
        :param kidId: (integer, query, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-02
        url = f"https://{base_url}/api/activity/gacha/daily-lesson-complete/check"
        payload = {
            "kidId": kidId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "检查今天是否已经通过每日课程完成增加过抽奖次数"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

