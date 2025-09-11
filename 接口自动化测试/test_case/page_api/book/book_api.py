
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class BookApi(BaseAPI):
    """书籍接口"""


    def createOrModifyBook(self, authorization, bookName, category, seriesId, storyType, DeviceType="web", **kwargs):
        """
        创建(带bookId)/修改一本书籍
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.?  2025-09-09
        # Creator: Baidi

        url = f"https://{base_url}/api/book/createOrModifyBook"
        payload = {
            "bookName": bookName,
            "category": category,
            "description": '',
            "file": "",
            "language": "zh",
            "maxAge": 10,
            "minAge": 2,
            "seriesId": seriesId,
            "storyType": storyType,
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建(带bookId)/修改一本书籍"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def book_list(self, authorization, searchKey="", DeviceType="web", **kwargs):
        """
        列出当前用户创建的书籍列表
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.?  2025-09-09
        # Creator: Baidi

        url = f"https://{base_url}/api/book/list"
        payload = {
            "page": 0,
            "pageSize": 10,
            "sortBy": "createTime",
            "sortDirection": "desc",
            "status": ""
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "列出当前用户创建的书籍列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def series_list(self, authorization, DeviceType="web", **kwargs):
        """
        更新故事书的翻译设置
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  ?  2025-09-08
        # Creator: Baidi
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增参数: `includeBookCover`, `bookCoverSize`
        url = f"https://{base_url}/api/book/series"
        payload = {
            "includeBookCover": False,
            "includeBookCount": False,
            "bookCoverSize": 3,
            "page": 0,
            "size": 10,
            "total": False,
            "translateLanguage": "en",
            "visibleOnly": True
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "更新故事书的翻译设置"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_translationSetting(self, authorization, bookId, isTranslatable=True, DeviceType="web", code=200):
        """
        更新故事书的翻译设置
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/book/{bookId}/translationSetting"
        payload = {
            "isTranslatable": isTranslatable
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "更新故事书的翻译设置"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if response.status_code != 403:
            response = response.json()
            return response

    def translationSetting(self, authorization, bookId, DeviceType="web", code=200):
        """
        获取故事书的翻译设置
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/book/{bookId}/translationSetting"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取故事书的翻译设置"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if code != 403:
            response = response.json()
            return response

    def getWordDefinition(self, authorization, word, interfaceLanguage, learningLanguage, DeviceType="web"):
        """
        获取故事书内单词释义
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/book/getWordDefinition"
        payload = {
            "word": word,
            "interfaceLanguage": interfaceLanguage,
            "learningLanguage": learningLanguage
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取故事书内单词释义"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def generateVideo(self, authorization, bookId, DeviceType="web", code=200):
        """
        根据故事书内容生成AI视频
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/book/generateVideo"
        payload = {
            "bookId": bookId,
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "获取故事书内单词释义"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def get_generateVideos(self, authorization, bookId, DeviceType="web", code=200):
        """
        获取故事书id获取AI视频信息
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/book/generateVideo"
        payload = {
            "bookId": bookId,
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取故事书内单词释义"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
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
        url = f"https://{base_url}/api/book/{bookId}/tormsToGlossary"
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

    def recommend_bookAndCourse(self, authorization, age='', courseNum=3, translateLanguage="en", DeviceType="web", code=200):
        """
        推荐体验课与故事书
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/api/book/recommend/bookAndCourse"
        payload = {
            "age": age,
            "courseNum": courseNum,
            "translateLanguage": translateLanguage
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "推荐体验课与故事书"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def recommend_newUserBookRules(self, authorization, DeviceType="web", code=200):
        """
        获取新用户推荐书籍规则
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/api/book/recommend/newUserBookRules"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取新用户推荐书籍规则"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if code != 401:
            response = response.json()
            return response

    def update_recommend_newUserBookRules(self, authorization, rules='', DeviceType="web", **kwargs):
        """
        设置新用户推荐书籍规则
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/api/book/recommend/newUserBookRules"
        payload = {
            "rules": rules
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "设置新用户推荐书籍规则"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def termsToGlossary(self, authorization, bookId, DeviceType="web"):
        """
        设置新用户推荐书籍规则
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-09
        # Creator: Baidi
        url = f"https://{base_url}/api/book/{bookId}/termsToGlossary"
        timestamp = str(int(time.time() * 1000))

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers)
        error_msg = "设置新用户推荐书籍规则"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response