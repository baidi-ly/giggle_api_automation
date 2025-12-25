import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminUserApi(BaseAPI):
    """书籍接口"""

    def sendemail(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        发送邮件
        :param email: (string, body, required) email 参数
        :param subject: (string, body, required) subject 参数
        :param content: (string, body, required) content 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-04
        url = f"https://{base_url}/admin/user/sendEmail"
        payload = {
            "email": "user@example.com",
            "subject": "邮件主题",
            "content": "邮件内容"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "发送邮件"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def deleteProblemUser_details(self, authorization, userId=0, batchSize=1500, dryRun=True, maxKidsLimit=100000, DeviceType="web", code=200, **kwargs):
        """
        删除问题用户及其相关数据
        :param userId: (integer, path, required) 问题用户ID
        :param batchSize: (integer, query, optional) 批处理大小
        :param dryRun: (boolean, query, optional) 是否只预览不执行删除
        :param maxKidsLimit: (integer, query, optional) 最大kids数量限制
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-05
        url = f"https://{base_url}/admin/user/delete-problem-user/{userId}"
        payload = {
            "batchSize": batchSize,
            "dryRun": dryRun,
            "maxKidsLimit": maxKidsLimit
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "删除问题用户及其相关数据"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deleteByDeviceId(self, authorization, deviceId, dryRun=True, DeviceType="web", code=200):
        """
        根据设备ID删除所有关联的用户及其kids
        :param deviceId: (string, query, required) 设备ID
        :param dryRun: (boolean, query, optional) 是否只预览不执行删除
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/admin/user/delete-by-device-id"
        payload = {
            "deviceId": deviceId,
            "dryRun": dryRun
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "根据设备ID删除所有关联的用户及其kids"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def trigger_email(self, authorization, DeviceType="web"):
        """
        手动触发非活跃用户通知
        :param deviceId: (string, query, required) 设备ID
        :param dryRun: (boolean, query, optional) 是否只预览不执行删除
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/admin/inactive-user/trigger-email"
        payload = {
            "timezone": '+08:00'
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "手动触发非活跃用户通知"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response