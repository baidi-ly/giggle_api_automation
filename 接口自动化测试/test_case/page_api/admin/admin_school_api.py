import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().admin_baseurl()


class AdminSchoolApi(BaseAPI):
    """admin学校系统接口"""

    def admin_create_class(self, authorization, teacherId, DeviceType="web", **kwargs):
        """
        创建班级
        :param className: (string, body, required) className 参数
        :param description: (string, body, required) description 参数
        :param grade: (integer, body, required) grade 参数
        :param subject: (string, body, required) subject 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/admin/school/class?teacherId={teacherId}"
        payload = {
            "className": "dibo_test_calss",
            "imageUrl": "",
            "room": "string",
            "subject": "Math",
            "teacherUserId": 0
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建班级"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def admin_class_list(self, authorization, teacherId, DeviceType="web", **kwargs):
        """
        获取用户的班级列表
        :param all: (boolean, query, optional) all
        :param page: (integer, query, optional) page
        :param size: (integer, query, optional) size
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/admin/school/class/list"
        payload = {
            'teacherId': teacherId,
            "all": True,
            "page": 0,
            "size": 20
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取用户的班级列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_admin_class(self, authorization, classId, teacherId, DeviceType="web", **kwargs):
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
        url = f"https://{base_url}/admin/school/class/{classId}?teacherId={teacherId}"
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
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def delete_admin_class(self, authorization, classId, teacherId, DeviceType="web"):
        """
        删除班级
        :param classId: (integer, path, required) classId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/admin/school/class/{classId}?teacherId={teacherId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除班级"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def batch_add_student(self, authorization, classId, teacherId, DeviceType="web", **kwargs):
        """
        批量添加学生
        :param classId: (integer, body, required) classId 参数
        :param studentNames: (array, body, required) studentNames 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/admin/school/student/batch?teacherId={teacherId}"
        payload = {
            "classId": classId,
            "studentNames": ['debbie', 'jerry']
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "批量添加学生"
        # assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def class_students(self, authorization, classId, teacherId, DeviceType="web", **kwargs):
        """
        获取班级学生列表
        :param classId: (integer, path, required) classId
        :param page: (integer, query, optional) page
        :param size: (integer, query, optional) size
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/admin/school/class/{classId}/students"
        payload = {
            "page": 0,
            "size": 20,
            'teacherId': teacherId
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取班级学生列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_student(self, authorization, studentId, teacherId, DeviceType="web", **kwargs):
        """
        更新学生信息
        :param studentId: (integer, path, required) studentId
        :param avatarUrl: (string, body, required) avatarUrl 参数
        :param studentName: (string, body, required) studentName 参数
        :param username: (string, body, required) username 参数
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/admin/school/student/{studentId}?teacherId={teacherId}"
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
        # assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def delete_student(self, authorization, studentId, teacherId, DeviceType="web"):
        """
        删除学生
        :param studentId: (integer, path, required) studentId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-25
        url = f"https://{base_url}/admin/school/student/{studentId}?teacherId={teacherId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除学生"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def migrate_student(self, authorization, teacherId, sourceClassIds=[], targetClassId=0, DeviceType="web", **kwargs):
        """
        迁移学生
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-05
        url = f"https://{base_url}/admin/school/student/migrate?teacherId={teacherId}"
        payload = {
            "sourceClassIds": sourceClassIds,
            "targetClassId": targetClassId
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "迁移学生"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def create_lesson(self, authorization, classId, teacherId, DeviceType="web", **kwargs):
        """
        创建课堂
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-17
        url = f"https://{base_url}/admin/school/lesson?teacherId={teacherId}"
        payload = {
          "classId": classId,
          "lessonName": "string",
          "resources": [
            {
              "id": 0,
              "resourceType": "string"
            }
          ],
          "teachingLanguage": "zh",
          "voiceRecognition": True
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建课堂"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def lesson_details(self, authorization, lessonId, teacherId, DeviceType="web"):
        """
        获取课堂详情
        :param lessonId: (integer, path, required) lessonId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-06
        url = f"https://{base_url}/admin/school/lesson/{lessonId}?teacherId={teacherId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取课堂详情"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_lesson(self, authorization, lessonId, classId, teacherId, DeviceType="web", **kwargs):
        """
        更新课堂信息
        :param lessonId: (integer, path, required) lessonId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-06
        url = f"https://{base_url}/admin/school/lesson/{lessonId}?teacherId={teacherId}"
        payload = {
            "classId": classId,
            "lessonName": '',
            "resources": [],
            "teachingLanguage": "en",
            "voiceRecognition": True
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新课堂信息"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def delete_lesson(self, authorization, lessonId, teacherId, DeviceType="web"):
        """
        删除课堂
        :param lessonId: (integer, path, required) lessonId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-06
        url = f"https://{base_url}/admin/school/lesson/{lessonId}?teacherId={teacherId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除课堂"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def class_lessons(self, authorization, classId, teacherId, DeviceType="web", **kwargs):
        """
        获取班级课堂列表
        :param classId: (integer, path, required) classId
        :param all: (boolean, query, optional) all
        :param keyword: (string, query, optional) keyword
        :param page: (integer, query, optional) page
        :param size: (integer, query, optional) size
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-05
        url = f"https://{base_url}/admin/school/class/{classId}/lessons?teacherId={teacherId}"
        payload = {
            "all": False,
            "keyword": '',
            "page": 0,
            "size": 20
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取班级课堂列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_students_lesson_groups(self, authorization, lessonId, teacherId, DeviceType="web", **kwargs):
        """
        更新课堂学生默认分组
        :param lessonId: (integer, path, required) lessonId
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-17
        url = f"https://{base_url}/admin/school/lesson/{lessonId}/groups?teacherId={teacherId}"
        payload = {
          "studentsGroup": [
            {
              "groupSeqNo": 0,
              "studentIds": [
                0
              ]
            }
          ]
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新课堂学生默认分组"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_students_class_groups(self, authorization, classId, teacherId, groupSeqNo=0, studentIds=[], DeviceType="web"):
        """
        更新班级学生默认分组
        :param classId: (integer, path, required) classId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-15
        url = f"https://{base_url}/admin/school/class/{classId}/groups?teacherId={teacherId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        payload = {
            "studentsGroup": [
                {
                    "groupSeqNo": groupSeqNo,
                    "studentIds": studentIds
                }
            ]
        }

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新班级学生默认分组"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def get_students_class_groups(self, authorization, classId, teacherId, DeviceType="web"):
        """
        获取班级学生默认分组
        :param classId: (integer, path, required) classId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-15
        url = f"https://{base_url}/admin/school/class/{classId}/groups?teacherId={teacherId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "更新班级学生默认分组"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def create_students_lesson_groups(self, authorization, lessonId, teacherId, groupCount, DeviceType="web"):
        """
        创建学生分组
        :param lessonId: (integer, path, required) lessonId
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-17
        url = f"https://{base_url}/admin/school/lesson/{lessonId}/groups?teacherId={teacherId}"
        payload = {
          "groupCount": groupCount
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建学生分组"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response
