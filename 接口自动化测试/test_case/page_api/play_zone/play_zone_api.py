import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class PlayZoneAPI(BaseAPI):
    """学习计划接口"""

    def random_line_drawing_word(self, authorization, kidId, DeviceType="web"):
        """
        学习计划包列表
        :param ageGroup: (string, query, optional) 年龄段筛选
        :param all: (boolean, query, optional) 是否获取全部
        :param category: (string, query, optional) 分类筛选
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/api/play-zone/random-line-drawing-word"
        payload = {
            "kidId": kidId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "学习计划包列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response