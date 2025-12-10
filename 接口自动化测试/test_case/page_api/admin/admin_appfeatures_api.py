import json
import time

from pandas import DataFrame

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminAppfeaturesApi(BaseAPI):
    """app灰度规则控制接口"""

    def getAppFeatures(self, authorization, DeviceType="web", code=200):
        """
        查询所有功能列表
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/app-features"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询所有功能列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def createAppFeatures(self, authorization, key, rules='', description='', DeviceType="web", code=200):
        """
        新增APP功能
        :param key: 必填，功能key（唯一标识符）
        :param description: 可选，功能描述
        :param rules: 可选，关联的规则ID列表（逗号分隔）
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/app-features"
        payload = {
            "key": key,           # 必填，功能key（唯一标识符）
            "description": description,        # 可选，功能描述
            "rules": rules                       # 可选，关联的规则ID列表（逗号分隔）
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "新增APP功能"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getAppFeaturesById(self, authorization, id, DeviceType="web", code=200):
        """
        根据ID查询功能
        :param id: (integer, path, required) id
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/app-features/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "根据ID查询功能"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updateAppFeatures(self, authorization, id, rules='', description='', DeviceType="web", code=200):
        """
        更新APP功能
        :param id: (integer, path, required) id
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/app-features/{id}"
        payload = {
            "description": description,
            "rules": rules
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新APP功能"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deleteAppFeatures(self, authorization, id, DeviceType="web", code=200):
        """
        删除APP功能
        :param id: (integer, path, required) id
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/app-features/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除APP功能"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getAppRulesByFeatureKey(self, authorization, featureKey, DeviceType="web", code=200):
        """
        查询功能的所有规则
        :param featureKey: (string, path, required) featureKey
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/app-features/{featureKey}/rules"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询功能的所有规则"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def createAppFeaturesRules(self, authorization, featureKey, ruleType, ruleValue, DeviceType="web", code=200):
        """
        新增灰度规则
        :param featureKey: 必填，功能key
        :param ruleType: 必填，规则类型：
            percent：按用户百分比灰度
            country：按国家限制（如 CN / CN_NOT）
            internalStaff：是否内部员工（true/false）
            channel：按渠道限制（如 ios, googleplay 等）
        :param ruleValue: 必填，规则值
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/app-features/rules"
        payload = {
            "featureKey": featureKey,
            "ruleType": ruleType,
            "ruleValue": ruleValue
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "新增灰度规则"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getAppFeaturesRulesById(self, authorization, id, DeviceType="web"):
        """
        根据ID查询规则
        :param id: (integer, path, required) id
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/app-features/rules/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "根据ID查询规则"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updateAppFeaturesRules(self, authorization, id, ruleType, ruleValue, DeviceType="web"):
        """
        更新灰度规则
        :param id: (integer, path, required) id
        :param ruleType: 可选，规则类型
        :param ruleValue: 可选，规则值
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/app-features/rules/{id}"
        payload = {
            "ruleType": ruleType,
            "ruleValue": ruleValue
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新灰度规则"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deleteAppFeaturesRules(self, authorization, id, DeviceType="web"):
        """
        删除灰度规则
        :param id: (integer, path, required) id
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/app-features/rules/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除灰度规则"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def batchDeleteAppFeatures(self, authorization, DeviceType="web"):
        """
        批量删除灰度规则
        :param ids: 必填，规则ID列表
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/admin/app-features/rules/batch-delete"
        payload = {
            "ids": [1, 2, 3]   
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers, json=payload)
        error_msg = "批量删除灰度规则"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

