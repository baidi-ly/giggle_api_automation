import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
official_baseurl = BaseAPI().official_baseurl()
admin_base_url = BaseAPI().admin_baseurl()


class AdminCourseinteractionApi(BaseAPI):
    """课程交互接口"""

    def course_interaction_list(self, authorization, courseId=0, courseName='', difficultyLevel='', page=0, size=20, DeviceType="web", code=200, **kwargs):
        """
        查询课程交互类型映射列表
        :param courseId: (integer, query, optional) courseId
        :param courseName: (string, query, optional) courseName
        :param difficultyLevel: (string, query, optional) difficultyLevel
        :param page: (integer, query, optional) page
        :param size: (integer, query, optional) size
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-30
        url = f"https://{base_url}/admin/course-interaction/list"
        payload = {
            "courseId": courseId,
            "courseName": courseName,
            "difficultyLevel": difficultyLevel,
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询课程交互类型映射列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def delete_courseInteraction(self, authorization, id=0, DeviceType="web", code=200, **kwargs):
        """
        删除课程交互类型映射
        :param id: (integer, path, required) id
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-30
        url = f"https://{base_url}/admin/course-interaction/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除课程交互类型映射"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def courseInteraction_import(self, authorization, file=None, DeviceType="web", code=200, **kwargs):
        """
        Excel批量导入课程交互类型映射
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-30
        url = f"https://{base_url}/admin/course-interaction/import"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, files=file)
        error_msg = "Excel批量导入课程交互类型映射"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

