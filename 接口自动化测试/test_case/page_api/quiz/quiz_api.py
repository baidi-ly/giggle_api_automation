import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class QuizApi(BaseAPI):
    """quiz接口"""

    def quizId_detail(self, authorization, quizId=0, DeviceType="web", code=200, **kwargs):
        """
        查询指定quiz的详情
        :param quizId: (integer, path, required) 测验ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-04
        url = f"https://{base_url}/api/quiz/{quizId}/detail"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询指定quiz的详情"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

