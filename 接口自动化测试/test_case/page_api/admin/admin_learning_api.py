
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminLearningApi(BaseAPI):
    """书籍接口"""

    def trigger_weekly_reports(self, authorization, DeviceType="web", code=200):
        """
        获取分类下所有课程
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/admin/learning-stats/trigger-weekly-reports"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "timezone": '+08:00',
        }
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "获取分类下所有课程"
        # assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response