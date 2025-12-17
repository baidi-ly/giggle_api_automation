import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class GameApi(BaseAPI):
    """游戏接口"""

    def __init__(self):
        '''有一个基础登录用户用于常规操作，当需要切换到其他用户时，调用接口传入该用户的bearerToken'''
        self.authorization = self.get_authorization()


    def search_game(self, authorization, key, DeviceType="web", **kwargs):
        """
        搜索游戏
        :param key: 搜索关键词，必填，不能为空
        :param inviteByCode: 设备类型
        :param kwargs: 可从kwargs中获取size，可选，默认10，最⼤100
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  修改基线，修改时间
        # updater: 接口维护人员
        # Update Details:  接口维护详情
        url = "https://{0}/api/game/search".format(base_url)
        payload = {
            "key": key,
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "搜索游戏"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getVisible(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        查询故事书Tab是否显示

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-20
        url = f"https://{base_url}/api/game/tab-storybook/visible"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询故事书Tab是否显示"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def drawing_word(self, authorization, word='', DeviceType="web", code=200, **kwargs):
        """
        游乐场画词接口
        :param authorization: (string, header, required) AuthToken
        :param word: (dict, body, optional) 单词
        :param DeviceType: (string, header, required) android/ios/web
        :param code: (integer) 预期HTTP状态码
        :return: API响应
        """
        url = f"https://{base_url}/api/play-zone/drawing-word"
        payload = {
            "word": word
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "游乐场画词接口"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，原因->{response.reason}{response.content}"
        try:
            return response.json()
        except json.decoder.JSONDecodeError:
            return False

    def get_playzone_price(self, authorization, playZoneId, DeviceType="web", code=200, **kwargs):
        """
        获取playZone价格
        :param authorization: (string, header, required) AuthToken
        :param playZoneId: (integer|string, path, required) 游乐场ID
        :param DeviceType: (string, header, required) android/ios/web
        :param code: (integer) 预期HTTP状态码
        :return: API响应
        """
        url = f"https://{base_url}/api/play-zone/{playZoneId}/price"
        payload = {
            "playZoneId": playZoneId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取playZone价格"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，原因->{response.reason}{response.content}"
        try:
            return response.json()
        except json.decoder.JSONDecodeError:
            return False

    def published_play_zones(self, authorization, DeviceType="web", code=200):
        """
        获取所有已发布的游戏列表
        """
        url = f"https://{base_url}/api/play-zone/published"
        payload = {
            "page": 0,
            "size": 100,
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取所有已发布的游戏列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，原因->{response.reason}{response.content}"
        try:
            return response.json()
        except json.decoder.JSONDecodeError:
            return False

    def reportReviewedWords(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        上报学习过的单词
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-10
        url = f"https://{base_url}/api/game/report-reviewed-words"
        payload = {
            "kidId": 0,
            "lessonId": 0,
            "wordIds": [0]
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "上报学习过的单词"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getUnreviewedWords(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取未复习的单词
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-10
        url = f"https://{base_url}/api/game/get-unreviewed-words"
        payload = {
          "kidId": 0,
          "courseIds": [
            0
          ]
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "获取未复习的单词"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getLearningstatus(self, authorization, kidId=0, DeviceType="web", code=200):
        """
        获取孩子学习状态
        :param kidId: (string, query, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-10
        url = f"https://{base_url}/api/game/learningStatus"
        payload = {
            "kidId": kidId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取孩子学习状态"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getDailyLearning(self, authorization, kidId, DeviceType="web", code=200):
        """
        检查用户今日是否完成学习
        :param kidId: (integer, path, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-15
        url = f"https://{base_url}/api/game/kids/{kidId}/daily-learning"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "检查用户今日是否完成学习"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def recorde_dailyLearning(self, authorization, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        记录用户今日学习完成状态
        :param kidId: (integer, path, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-15
        url = f"https://{base_url}/api/game/kids/{kidId}/daily-learning"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "记录用户今日学习完成状态"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getAlltopcategory(self, authorization, DeviceType="web", code=200):
        """
        获取顶层课程目录列表

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-02
        url = f"https://{base_url}/api/game/series/allTopCategory"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取顶层课程目录列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getAllsubcategory(self, authorization, parentId, DeviceType="web", code=200):
        """
        获取课程子目录列表
        :param parentId: (integer, query, required) parentId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-02
        url = f"https://{base_url}/api/game/series/allSubCategory"
        payload = {
            "parentId": parentId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取课程子目录列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def gameListall(self, authorization, categoryId, DeviceType="web", code=200):
        """
        获取分类下所有课程
        :param categoryId: (integer, query, required) categoryId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-02
        url = f"https://{base_url}/api/game/content/listAll"
        payload = {
            "categoryId": categoryId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取分类下所有课程"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def learningStatusV2(self, authorization, kidId, DeviceType="web", code=200):
        """
        检查今天是否已经通过每日课程完成增加过抽奖次数
        :param categoryId: (integer, query, optional) categoryId
        :param kidId: (string, query, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-02
        url = f"https://{base_url}/api/game/learningStatus/v2"
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

    def queryCourseStrategy(self, authorization, courseId='', level='', DeviceType="web"):
        """
        查询课程策略配置
        :param courseId: (string, query, optional) 课程ID（非必传）
        :param level: (integer, query, optional) 用户等级1-20（非必传）
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/api/game/courseStrategy/query"
        payload = {
            "courseId": courseId,
            "level": level
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询课程策略配置"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def completelearning(self, authorization, course_id, kid_id, course_name='', completedAt=1704787200000,
                         reward=True, DeviceType="web"):
        """
        记录孩子完成一门课程的学习
        :param request: (object, body, required) request
        :param reward: (boolean, query, optional) reward
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-17
        url = f"https://{base_url}/api/game/completeLearning"
        payload1 = {"reward": reward}
        payload2 = {
            "id": course_id,
            "kidId": kid_id,
            "completedAt": completedAt,
            "lessonName": course_name
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload1, json=payload2)
        error_msg = "记录孩子完成一门课程的学习"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response