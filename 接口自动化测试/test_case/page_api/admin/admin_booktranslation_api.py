import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminBooktranslationApi(BaseAPI):
    """书籍翻译接口"""

    def concurrent_threshold(self, authorization, threshold, DeviceType="web", code=200, **kwargs):
        """
        更新书籍翻译并发阈值设置
        :param threshold: (integer, body, required) threshold 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.20.0  &  2025-01-27
        url = f"https://{base_url}/admin/book-translation/concurrent-threshold"
        payload = {
            "threshold": threshold
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "更新书籍翻译并发阈值设置"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False