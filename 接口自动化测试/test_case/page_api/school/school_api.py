
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class SchoolApi(BaseAPI):
    """学校系统接口"""

    def school_class(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        创建班级
        :param className: (string, body, required) className 参数
        :param description: (string, body, required) description 参数
        :param grade: (integer, body, required) grade 参数
        :param subject: (string, body, required) subject 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/api/school/class"
        payload = {
            "className": "三年级一班",
            "description": "三年级英语学习班",
            "grade": 3,
            "subject": "English"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建班级"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if code != 401:
            response = response.json()
            return response

    def getList(self, authorization, all=False, page=0, size=10, DeviceType="web", code=200, **kwargs):
        """
        获取用户的班级列表
        :param all: (boolean, query, optional) all
        :param page: (integer, query, optional) page
        :param size: (integer, query, optional) size
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/api/school/class/list"
        payload = {
            "all": all,
            "page": page,
            "size": size
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取用户的班级列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except:
            pass

    def putAuto(self, authorization, classId=0, DeviceType="web", code=200, **kwargs):
        """
        更新班级信息
        :param classId: (integer, path, required) classId
        :param className: (string, body, required) className 参数
        :param imageUrl: (string, body, required) imageUrl 参数
        :param room: (string, body, required) room 参数
        :param subject: (string, body, required) subject 参数
        :param teacherUserId: (integer, body, required) teacherUserId 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/api/school/class/{classId}"
        payload = {
            "className": "dd",
            "imageUrl": "https://baidu.com",
            "room": "room1",
            "subject": "english",
            "teacherUserId": 0
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新班级信息"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except:
            return False

    def deleteAuto(self, authorization, classId=0, DeviceType="web", code=200, **kwargs):
        """
        删除班级
        :param classId: (integer, path, required) classId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/api/school/class/{classId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除班级"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except:
            return False

    def batch(self, authorization, classId, DeviceType="web", code=200, **kwargs):
        """
        批量添加学生
        :param classId: (integer, body, required) classId 参数
        :param studentNames: (array, body, required) studentNames 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/api/school/student/batch"
        payload = {
            "classId": classId,
            "studentNames": ['debbie', 'jerry']
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "批量添加学生"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except:
            return False

    def getStudents(self, authorization, classId=0, page=0, size=10, DeviceType="web", code=200, **kwargs):
        """
        获取班级学生列表
        :param classId: (integer, path, required) classId
        :param page: (integer, query, optional) page
        :param size: (integer, query, optional) size
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/api/school/class/{classId}/students"
        payload = {
            "page": page,
            "size": size
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取班级学生列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def putAuto1(self, authorization, studentId=0, DeviceType="web", code=200, **kwargs):
        """
        更新学生信息
        :param studentId: (integer, path, required) studentId
        :param avatarUrl: (string, body, required) avatarUrl 参数
        :param studentName: (string, body, required) studentName 参数
        :param username: (string, body, required) username 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/api/school/student/{studentId}"
        payload = {
            "avatarUrl": "string",
            "studentName": "xxx",
            "username": "qqq"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新学生信息"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def deleteAuto1(self, authorization, studentId=0, DeviceType="web", code=200, **kwargs):
        """
        删除学生
        :param studentId: (integer, path, required) studentId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/api/school/student/{studentId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除学生"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def lesson(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        创建课堂
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-06
        url = f"https://{base_url}/api/school/lesson"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "创建课堂"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

