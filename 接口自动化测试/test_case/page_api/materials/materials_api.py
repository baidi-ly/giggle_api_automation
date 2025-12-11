import json
import os
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

    def download_materials(self, authorization, key, fileName, DeviceType="web", fileType="msgpack", real_time=False, **kwargs):
        """
        下载材料
        :param key: (string, query, required) key
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-05
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        if key:
            url = f"https://{base_url}/api/materials/download"
            payload = {
                "key": key
            }
            response = requests.request("GET", url, headers=headers, params=payload, allow_redirects=False)
        else:
            response = requests.request("GET", kwargs.get('url'), headers=headers, allow_redirects=False)
        if response.status_code == 302:
            redirect_url = response.headers.get('Location')
            # redirect_url = "https://" + self.baseurl() + redirect_url
            response = requests.get(redirect_url, headers=headers)
        error_msg = "下载材料"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        file_path = os.getcwd() + fr'/report/{fileName}.{fileType}'
        if not real_time:
            with open(file_path, 'wb') as file:
                file.write(response.content)
        else:
            with open(file_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        file.write(chunk)
                        file.flush()  # 刷新缓冲
                        os.fsync(file.fileno())  # 可选：强制落盘
