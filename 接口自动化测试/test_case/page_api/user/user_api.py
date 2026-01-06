import json
import time

from test_case.page_api.base_api import BaseAPI
from utils.rsa_manage import password_base64

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class UserApi(BaseAPI):
    """书籍接口"""

    def get_videoWhitelist(self, authorization, DeviceType="web"):
        """
        获取视频白名单用户列表
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/user/videoWhitelist"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取视频白名单用户列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_videoWhitelist(self, authorization, userIds:[], DeviceType="web"):
        """
        视频白名单用户全量更新
        :param userIds: 更新后的用户列表
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/user/videoWhitelist"
        payload = {
            "userIds": userIds
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "视频白名单用户全量更新"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def bindWechat(self, authorization, code, DeviceType="web", status_code=200, **kwargs):
        """
        绑定微信账号
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/api/user/bindWechat"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "code": code
        }
        payload = self.request_body(payload, **kwargs)
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "绑定微信账号"
        assert response.status_code == status_code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if response.status_code != 401:
            response = response.json()
            return response

    def unbindWechat(self, authorization, DeviceType="web", code=200):
        """
        解绑微信账号
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/user/unbindWechat"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers)
        error_msg = "解绑微信账号"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if code != 403:
            response = response.json()
            return response

    def bindApple(self, authorization, identifyToken='', DeviceType="web", code=200, **kwargs):
        """
        绑定Apple账号
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/user/bindApple"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "identifyToken": identifyToken
        }
        payload = self.request_body(payload, **kwargs)
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "绑定Apple账号"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def unbindApple(self, authorization, DeviceType="web", code=200):
        """
        解绑Apple账号
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/user/unbindApple"
        payload = {}

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "解绑Apple账号"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def profile(self, authorization, bindAccount, DeviceType="web"):
        """
        用户注册接口
        :param bindAccount: 用户名，3-20位字符
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/user/profile".format(base_url)
        payload = {
            "bindAccount": bindAccount
        }

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "解绑Apple账号"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def refresh(self, authorization, bindAccount, DeviceType="web"):
        """
        用户注册接口
        :param bindAccount: 用户名，3-20位字符
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增 `bindAccount` 字段
        url = "https://{0}/user/refresh".format(base_url)
        payload = {
            "bindAccount": bindAccount
        }

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "解绑Apple账号"
        assert response.status_code in [200, 201], f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def aiStoryCreation(self, authorization, bookId=0, DeviceType="web", code=200, **kwargs):
        """
        AI创建故事书消耗giggles
        :param bookId: (integer, path, required) bookId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-16
        url = f"https://{base_url}/api/user/aiStoryCreation/{bookId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "AI创建故事书消耗giggles"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getAzureconfig(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取 Azure 配置

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-16
        url = f"https://{base_url}/api/user/azureConfig"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取 Azure 配置"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def sendemail(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        发送邮箱验证码接口
        :param email: (string, body, required) email 参数
        :param scene: (string, body, required) scene 参数
        :param language: (string, body, required) language 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-26
        url = f"https://{base_url}/api/user/sendEmail"
        payload = {
            "email": "bd22434@163.com",
            "scene": "RESET_PASSWORD",
            "language": "zh-CN"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "发送邮箱验证码接口"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def abtest_status(self, authorization, status=2, DeviceType="web", code=200, **kwargs):
        """
        设置用户AB测试状态
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-24
        url = f"https://{base_url}/api/user/abtest/status"
        payload = {
            "status": status
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "设置用户AB测试状态"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def get_abtest_status(self, authorization, status=2, DeviceType="web", code=200, **kwargs):
        """
        设置用户AB测试状态
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-24
        url = f"https://{base_url}/api/user/abtest/status"
        payload = {
            "status": status
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "设置用户AB测试状态"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def questionnaire(self, authorization, kidId=0, learningLevel='', DeviceType="web", code=200, **kwargs):
        """
        提交问卷设置学习水平
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-29
        url = f"https://{base_url}/api/user/kid/questionnaire"
        payload = {
            "kidId": kidId,
            "learningLevel": learningLevel
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "提交问卷设置学习水平"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getLearningLevel(self, authorization, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        获取孩子的学习水平
        :param kidId: (integer, path, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-29
        url = f"https://{base_url}/api/user/kid/{kidId}/learning-level"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取孩子的学习水平"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deleteDeleteaccount(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        删除用户账户

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-05
        url = f"https://{base_url}/api/user/deleteAccount"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除用户账户"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getUserKids(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取当前用户的kids

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-07
        url = f"https://{base_url}/api/user/kids"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取当前用户的kids"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def editkid(self, authorization, kid_id, kid_name, DeviceType="web", code=200, **kwargs):
        """
        editKid
        :param kidData: (object, body, required) kidData
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-24
        url = f"https://{base_url}/api/user/editKid"
        payload = {
            "id": kid_id,
            "name": kid_name,
            "yearOfBirth": 2018,
            "gender": 1,
            "avatarUrl": "https://cdn.example.com/avatar/emily.png"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "editKid"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def registerInfo_sync(self, authorization, username, password, DeviceType="web", code=200, **kwargs):
        """
        用户第三方登录后信息注册同步
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-24
        url = f"https://{base_url}/api/user/registerInfo/sync"
        password = password_base64(password)
        payload = {
            "countryCode": "US",
            "school": "Giggle Elementary",
            "username": username,
            "password": password
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "用户第三方登录后信息注册同步"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def checkPhone(self, authorization, countryCode, phoneNumber, DeviceType="web", code=200):
        """
        检测手机号是否已注册
        :param countryCode: (string, query, required) 国家代码
        :param phoneNumber: (string, query, required) 电话号码
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-01
        url = f"https://{base_url}/api/user/checkPhone"
        payload = {
            "countryCode": countryCode,
            "phoneNumber": phoneNumber
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "检测手机号是否已注册"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getSearch(self, authorization, key, DeviceType="web", code=200):
        """
        根据用户名/email搜索用户
        :param key: (string, query, required) key
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-01
        url = f"https://{base_url}/api/user/search"
        payload = {
            "key": key
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据用户名/email搜索用户"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getDailyLessonLimit(self, authorization, kidId, DeviceType="web", code=200):
        """
        获取孩子的每日课程数量限制
        :param kidId: (integer, path, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-01
        url = f"https://{base_url}/api/user/kid/{kidId}/daily-lesson-limit"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取孩子的每日课程数量限制"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def dailyLessonLimit(self, authorization, kidId, dailyLessonLimit, DeviceType="web", code=200):
        """
        设置孩子的每日课程数量限制
        :param kidId: (integer, path, required) kidId
        :param dailyLessonLimit: (integer, query, required) dailyLessonLimit
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-01
        url = f"https://{base_url}/api/user/kid/{kidId}/daily-lesson-limit"
        payload = {
            "dailyLessonLimit": dailyLessonLimit
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "设置孩子的每日课程数量限制"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updatelanguage(self, authorization, language='zh', DeviceType="web", code=200):
        """
        更新用户语言偏好
        :param language: (string, query, required) language
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-02
        url = f"https://{base_url}/api/user/updateLanguage"
        payload = {
            "language": language
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "更新用户语言偏好"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def createkid(self, authorization, name, yearOfBirth=2018, gender=1,
                  avatarUrl='https://images.unsplash.com/photo-1503454537195-1dcabb73ffb9?w=400&auto=format&fit=crop&q=80',
                  DeviceType="web", code=200, **kwargs):
        """
        新建孩子
        :param kidData: (object, body, required) kidData
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-08
        url = f"https://{base_url}/api/user/createKid"
        payload = {
            "name": name,
            "yearOfBirth": yearOfBirth,
            "gender": gender,
            "avatarUrl": avatarUrl
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "新建孩子"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deletekid(self, authorization, id, DeviceType="web", code=200):
        """
        删除孩子
        :param id: (integer, query, required) id
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-08
        url = f"https://{base_url}/api/user/deleteKid"
        payload = {
            "id": id
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers, params=payload)
        error_msg = "删除孩子"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getDailyLessonLimitNew(self, authorization, kidId='', DeviceType="web", code=200):
        """
        获取孩子的每日课程数量限制
        :param kidId: (integer, query, optional) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-09
        url = f"https://{base_url}/api/user/kid/daily-lesson-limit"
        payload = {
            "kidId": kidId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取孩子的每日课程数量限制"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def existingKidLevelInit(self, authorization, kidId, DeviceType="web", code=200):
        """
        老用户Kid学习等级初始化
        :param kidId: (integer, path, required) kidId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-09
        url = f"https://{base_url}/api/user/kid/{kidId}/existing-kid-level-init"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "老用户Kid学习等级初始化"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def creategGuestUser(self, authorization, language='ch', timezone='+8:00', DeviceType="web"):
        """
        创建游客账户
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/api/user/guest/create"
        payload = {
            "language": language,
            "timezone": timezone
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建游客账户"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def userDevice(self, authorization, DeviceType="web"):
        """
        通过deviceId获取用户信息

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/api/user/info/device"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "通过deviceId获取用户信息"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def profileSummary(self, authorization, userId, DeviceType="web"):
        """
        用户信息总览
        :param userId: (integer, query, optional) userId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2026-01-06
        url = f"https://{base_url}/api/user/profileSummary"
        payload = {
            "userId": userId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "用户信息总览"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def isFollowUser(self, authorization, followedId, DeviceType="web"):
        """
        判断是否关注
        :param followedId: (integer, query, required) followedId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2026-01-06
        url = f"https://{base_url}/api/user/isFollow"
        payload = {
            "followedId": followedId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "判断是否关注"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def followUser(self, authorization, followedId, DeviceType="web"):
        """
        新增关注
        :param followedId: (integer, query, required) followedId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2026-01-06
        url = f"https://{base_url}/api/user/follow"
        payload = {
            "followedId": followedId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "新增关注"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def deleteFollowUser(self, authorization, followedId, DeviceType="web"):
        """
        取消关注
        :param followedId: (integer, query, required) followedId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2026-01-06
        url = f"https://{base_url}/api/user/follow"
        payload = {
            "followedId": followedId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers, params=payload)
        error_msg = "取消关注"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

