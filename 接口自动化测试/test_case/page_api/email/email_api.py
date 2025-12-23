import json
import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
AUTH_KEY = RunConfig.AUTH_KEY


class EmailApi(BaseAPI):

    def triggerEmail(self, authorization, bookId, languageCode, DeviceType="web"):
        url = f"{self.base}/admin/inactive-user/trigger-email"
        payload = {
            "bookId": bookId,
            "languageCode": languageCode
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "添加语言包处理任务到队列"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def queryEmailPushList(self, authorization, page=0, pageSize=20, DeviceType="web"):
        url = f"{self.base}/admin/email/queryEmailPushList"
        payload = {
            "page": page,
            "pageSize": pageSize
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "添加语言包处理任务到队列"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getEmailContent(self, authorization, emailId, DeviceType="web"):
        url = f"{self.base}/admin/email/getEmailContent/{emailId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "添加语言包处理任务到队列"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def queryUnsubscribeEmails(self, authorization, page=0, pageSize=20, DeviceType="web"):
        url = f"{self.base}/admin/email/queryUnsubscribeEmails"
        payload = {
            "page": page,
            "pageSize": pageSize
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "添加语言包处理任务到队列"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response