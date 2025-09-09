
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class PosterApi(BaseAPI):
    """书籍接口"""

    def poster_generate(self, authorization, direction, scale, DeviceType="web"):
        """
        上传通用资源文件
        :param:
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增参数: `direction`, `scale`
        url = f"https://{base_url}/poster/generate"
        payload = {
            "direction": direction,
            "scale": scale
        }

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "上传通用资源文件"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response
