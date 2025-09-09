import time

from 接口自动化测试.config import RunConfig
from 接口自动化测试.test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
AUTH_KEY = RunConfig.AUTH_KEY


class LearningApi(BaseAPI):
    """孩子学习统计接口"""

    def learning_stats(self, kidId, authorization="", DeviceType="web", code=200):
        """
        获取孩子学习统计数据
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        # Update Date:
        # updater:
        # Update Details:
        url = f"https://{base_url}/api/learning/stats/{kidId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取孩子学习统计数据"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if code != 401:
            response = response.json()
            return response

    def daily_learning(self, kidId, authorization="", DeviceType="web", code=200):
        """
        获取孩子今日学习详情
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        # Update Date:
        # updater:
        # Update Details:
        url = f"https://{base_url}/api/learning/daily/{kidId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取孩子今日学习详情"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if code != 401:
            response = response.json()
            return response

    def daily_learning_report(self, kidId, date='', authorization="", DeviceType="web"):
        """
        生成指定孩子的学习情况报表数据
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        # Update Date:
        # updater:
        # Update Details:
        url = f"https://{base_url}/api/learning/daily-report/{kidId}"
        payload = {
            "date": date
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "生成指定孩子的学习情况报表数据"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def weekly_learning(self, kidId, authorization="", startDate="", endDate="", DeviceType="web"):
        """
        获取指定孩子一周的学习情况（自然周：周一到周日）
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        # Update Date:
        # updater:
        # Update Details:
        url = f"https://{base_url}/api/learning/weekly/{kidId}"
        payload = {
            "startDate": startDate,
            "endDate": endDate
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取指定孩子一周的学习情况（自然周：周一到周日）"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        assert "data" in response,  f"{error_msg}返回结果没有data数据，url->{url}，response->{response}"
        return response["data"]

    def weekly_learning_report(self, kidId, authorization="", startDate="", endDate="", DeviceType="web"):
        """
        获取指定孩子一周的学习报告
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        # Update Date:
        # updater:
        # Update Details:
        url = f"https://{base_url}/api/learning/weekly-report/{kidId}"
        payload = {
            "startDate": startDate,
            "endDate": endDate
        }

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取指定孩子一周的学习报告"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def daily_storybook_report(self, kidId, date="", authorization="", DeviceType="web"):
        """
        生成故事书报告
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        # Update Date:
        # updater:
        # Update Details:
        url = f"https://{base_url}/api/learning/daily-report/storybook/{kidId}"
        payload = {
            "date": date
        }

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "生成故事书报告"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def daily_challenge_report(self, kidId, date="", authorization="", DeviceType="web"):
        """
        生成挑战课报告
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        # Update Date:
        # updater:
        # Update Details:
        url = f"https://{base_url}/api/learning/daily-report/challenge/{kidId}"
        payload = {
            "date": date
        }

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "生成挑战课报告"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def daily_flashcard_report(self, kidId, date="", authorization="", DeviceType="web"):
        """
        生成闪卡报告
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        # Update Date:
        # updater:
        # Update Details:
        url = f"https://{base_url}/api/learning/daily-report/flashcard/{kidId}"
        payload = {
            "date": date
        }

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "生成闪卡报告"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response
















