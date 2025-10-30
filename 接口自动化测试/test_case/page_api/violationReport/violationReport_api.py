
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class ViolationReportApi(BaseAPI):
    """违规举报相关接口"""

    def report(self, authorization, content='', images=None, DeviceType="web", code=200, **kwargs):
        """
        提交违规举报
        :param authorization: (string, header, required) AuthToken
        :param content: (string, body, required) 举报内容
        :param images: (list, body, optional) 图片列表
        :param DeviceType: (string, header, required) android/ios/web
        :param code: (integer) 期望的HTTP状态码
        :return: API接口原始响应
        """
        url = f"https://{base_url}/api/violation-report"
        payload = {
            "content": content,
            "images": images if images is not None else []
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "提交违规举报"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，原因->{response.reason}{response.content}"
        try:
            return response.json()
        except Exception:
            return False