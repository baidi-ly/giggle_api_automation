
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

