import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminCastApi(BaseAPI):
    """后台博客接口"""

    def getAlbums(self, authorization, languageCode='', DeviceType="web", code=200, **kwargs):
        """
        查询播客的专辑
        :param languageCode: (string, query, optional) 语言编码
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-05
        url = f"https://{base_url}/admin/cast/albums"
        payload = {
            "languageCode": languageCode
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询播客的专辑"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def createCast(self, authorization, file=None, DeviceType="web", **kwargs):
        """
        创建播客
        :param album: (string, query, optional) 播客专辑（分类）
        :param author: (string, query, optional) 播客作者
        :param description: (string, query, optional) 播客描述
        :param isPublished: (boolean, query, optional) 是否发布
        :param sortOrder: (integer, query, optional) 排序顺序，数值越小排序越靠前
        :param title: (string, query, required) 播客标题
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-16
        url = f"https://{base_url}/admin/cast"
        payload = {
            "album": '',
            "author": '',
            "description": '',
            "isPublished": False,
            "sortOrder": 0,
            "title": ''
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, data=payload, files=file)
        error_msg = "创建播客"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response
