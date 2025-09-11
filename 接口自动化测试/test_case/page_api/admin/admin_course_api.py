
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminApi(BaseAPI):
    """书籍接口"""

    def export_byTheme(self, authorization, theme, DeviceType="web"):
        """
        根据主题导出课程词汇
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/admin/course/export-by-theme"
        payload = {
            "theme": theme
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据主题导出课程词汇"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def trial_list(self, authorization, DeviceType="web", code=200):
        """
        查看体验课的课程
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/admin/course/list-trial"
        timestamp = str(int(time.time() * 1000))

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers)
        error_msg = "查看体验课的课程"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if code != 401:
            response = response.json()
            return response

    def update_to_trial(self, authorization, courseId, DeviceType="web"):
        """
        标记课程为体验课
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/admin/course/update-trial"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "courseId": courseId
        }
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "标记课程为体验课"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def remove_trial(self, authorization, courseId, DeviceType="web"):
        """
        移除课程体验课的标记
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/admin/course/remove-trial"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "courseId": courseId
        }

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "移除课程体验课的标记"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def blockedIds(self, authorization, DeviceType="web"):
        """
        获取屏蔽的课程ID列表
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/admin/course/blockedIds"
        timestamp = str(int(time.time() * 1000))

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取屏蔽的课程ID列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_blockedIds(self, authorization, blockedIds, DeviceType="web"):
        """
        更新屏蔽的课程ID列表
        :param blockedIds: 用户邮箱
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/admin/course/blockedIds"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "blockedIds": blockedIds
        }

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "更新屏蔽的课程ID列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def course_listAll(self, authorization, categoryId, DeviceType="web", code=200):
        """
        获取分类下所有课程
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/admin/course/listAll'"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "categoryId": categoryId
        }
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "获取分类下所有课程"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response