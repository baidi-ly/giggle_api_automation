
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class InteractionApi(BaseAPI):
    """交互事件接口"""

    def update_translationSetting(self, authorization, eventName, courseId, lessonType, DeviceType="web"):
        """
        上报用户交互事件
        :param eventName: 事件名
        :param courseId: 课程id
        :param lessonType: 课程类型
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/interaction/event"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "eventName": eventName,
            "params": {
                "courseId": courseId,
                "lessonType": lessonType
            }
        }
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "上报用户交互事件"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

