
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class MaterialsApi(BaseAPI):
    """书籍接口"""

    def uploadCommonResource(self, authorization, contentType='', file=None, DeviceType="web", code=200, **kwargs):
        """
        uploadCommonResource
        :param contentType: (string, query, optional) contentType
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-04
        url = f"https://{base_url}/api/materials/upload-common-resource"
        payload = {
            "contentType": contentType
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, data=payload, files=file)
        error_msg = "uploadCommonResource"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

