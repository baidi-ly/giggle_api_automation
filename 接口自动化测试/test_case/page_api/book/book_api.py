
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class BookApi(BaseAPI):
    """书籍接口"""

    def series_list(self, authorization, includeBookCover, bookCoverSize, DeviceType="web"):
        """
        更新故事书的翻译设置
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增参数: `includeBookCover`, `bookCoverSize`
        url = f"https://{base_url}/book/series/list"
        payload = {
            "includeBookCover": includeBookCover,
            "bookCoverSize": bookCoverSize
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "更新故事书的翻译设置"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_translationSetting(self, authorization, bookId, DeviceType="web"):
        """
        更新故事书的翻译设置
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/book/{bookId}/translationSetting"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers)
        error_msg = "更新故事书的翻译设置"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def translationSetting(self, authorization, bookId, DeviceType="web"):
        """
        获取故事书的翻译设置
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/book/{bookId}/translationSetting"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取故事书的翻译设置"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getWordDefinition(self, authorization, DeviceType="web"):
        """
        获取故事书内单词释义
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/book/getWordDefinition"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取故事书内单词释义"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def generateVideo(self, authorization, bookId, DeviceType="web"):
        """
        根据故事书内容生成AI视频
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/book/generateVideo"
        payload = {
            "bookId": bookId,
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "获取故事书内单词释义"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def get_generateVideos(self, authorization, bookId, DeviceType="web"):
        """
        获取故事书id获取AI视频信息
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/book/generateVideo"
        payload = {
            "bookId": bookId,
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取故事书内单词释义"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def tormsToGlossary(self, authorization, bookId, DeviceType="web"):
        """
        更新术语库
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/book/{bookId}/tormsToGlossary"
        payload = {
            "bookId": bookId,
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取故事书内单词释义"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def recommend_bookAndCourse(self, authorization, DeviceType="web"):
        """
        推荐体验课与故事书
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/book/recommend/bookAndCourse"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "推荐体验课与故事书"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def recommend_newUserBookRules(self, authorization, DeviceType="web"):
        """
        获取新用户推荐书籍规则
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/book/recomment/newUserBookRules"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取新用户推荐书籍规则"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_recommend_newUserBookRules(self, authorization, ruleIds, DeviceType="web"):
        """
        设置新用户推荐书籍规则
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/book/recomment/newUserBookRules"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "ruleIds": ruleIds
        }

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "设置新用户推荐书籍规则"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

