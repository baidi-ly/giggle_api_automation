import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
official_baseurl = BaseAPI().official_baseurl()
admin_base_url = BaseAPI().admin_baseurl()


class AdminCourseApi(BaseAPI):
    """书籍接口"""

    def export_byTheme(self, authorization, theme, DeviceType="web", code=200):
        """
        根据主题导出课程词汇
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{admin_base_url}/admin/course/export-by-theme"
        payload = {
            "theme": theme
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据主题导出课程词汇"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if response.status_code != 401:
            response = response.json()
            return response

    def trial_list(self, authorization, DeviceType="web", code=200):
        """
        查看体验课的课程
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{admin_base_url}/admin/course/list-trial"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查看体验课的课程"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if code != 401:
            response = response.json()
            return response

    def update_to_trial(self, authorization, courseId, DeviceType="web"):
        """
        标记课程为体验课
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{admin_base_url}/admin/course/update-trial"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "courseId": courseId
        }
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "标记课程为体验课"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def remove_trial(self, authorization, courseId, DeviceType="web"):
        """
        移除课程体验课的标记
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{admin_base_url}/admin/course/remove-trial"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "courseId": courseId
        }

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "移除课程体验课的标记"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def blockedIds(self, authorization, DeviceType="web"):
        """
        获取屏蔽的课程ID列表
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{admin_base_url}/admin/course/blockedIds"
        timestamp = str(int(time.time() * 1000))

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取屏蔽的课程ID列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_blockedIds(self, authorization, courseIds, DeviceType="web"):
        """
        更新屏蔽的课程ID列表
        :param blockedIds: 用户邮箱
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{admin_base_url}/admin/course/blockedIds"
        timestamp = str(int(time.time() * 1000))
        payload = {
          "courseIds": courseIds
        }

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新屏蔽的课程ID列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def course_listAll(self, authorization, categoryId, DeviceType="web", code=200):
        """
        获取分类下所有课程
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{admin_base_url}/admin/course/listAll"
        timestamp = str(int(time.time() * 1000))
        payload = {
            "categoryId": categoryId
        }
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取分类下所有课程"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getSpelrules(self, authorization, abTest=False, DeviceType="web", code=200, **kwargs):
        """
        获取体验课程推荐SpEL表达式规则
        :param abTest: (boolean, query, optional) abTest
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-20
        url = f"https://{admin_base_url}/admin/course/recommend/spelRules"
        payload = {
            "abTest": abTest
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取体验课程推荐SpEL表达式规则"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def spelrules(self, authorization, rules='', abTest=False, DeviceType="web", code=200, **kwargs):
        """
        设置体验课程推荐SpEL表达式规则
        :param rules: (object, body, required) rules
        :param abTest: (boolean, query, optional) abTest
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-20
        url = f"https://{admin_base_url}/admin/course/recommend/spelRules"
        payload1 = {
            "abTest": abTest
        }
        payload2 = {
          "rules": {
            "1": "#age >= 3 && #age <= 5",
            "2": "#age >= 6 && #age <= 8",
            "3": "#age >= 9 && #age <= 12",
            "4": "#age >= 13 && #age <= 15",
            "5": "#age >= 16"
          }
        }
        payload2 = self.request_body(payload2, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload1, json=payload2)
        error_msg = "设置体验课程推荐SpEL表达式规则"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def generateTags(self, authorization, courseId=1, DeviceType="web", code=200, **kwargs):
        """
        AI生成课程标签
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-29
        url = f"https://{admin_base_url}/admin/course/generate-tags"
        payload = {
          "courseId": courseId
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "AI生成课程标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def createLevelSkill(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        新增等级技能
        :param learningLevel: (object, string, required) 学习等级
        :param educationType: (object, string, required) 教育类型
        :param skill: (object, string, required) 技能名称
        :param necessary: (object, string, required) 是否必修
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-10
        url = f"https://{base_url}/admin/level-skills"
        payload = {
            "learningLevel": "L1",
            "educationType": "Early Years",
            "skill": "Reading-Level1",
            "necessary": True
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "新增等级技能"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def course_skills(self, authorization, page=0, size=100, skill='', DeviceType="web", code=200, **kwargs):
        """
        分页查询课程等级技能列表
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :param skill: (string, query, optional) 技能名称搜索
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-10
        url = f"https://{admin_base_url}/admin/level-skills/list"
        payload = {
            "page": page,
            "size": size,
            "skill": skill  # Reading\Level1\Writing
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "分页查询课程等级技能列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updateLevelSkills(self, authorization, skill_id, DeviceType="web", code=200, **kwargs):
        """
        更新等级技能
        :param ids: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-10
        url = f"https://{base_url}/admin/level-skills/{skill_id}"
        payload = {
            "educationType": "string",
            "necessary": True,
            "prerequisiteSkill": "string",
            "parentSkill": "string"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers, json=payload)
        error_msg = "更新等级技能"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deleteLevelskills(self, authorization, ids:list, DeviceType="web", code=200, **kwargs):
        """
        批量删除等级技能
        :param ids: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-10
        url = f"https://{base_url}/admin/level-skills/batch-delete"
        payload = {
            "ids": ids
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers, json=payload)
        error_msg = "批量删除等级技能"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def levelSkills_import(self, authorization, file=None, DeviceType="web", code=200, **kwargs):
        """
        批量导入学习技能
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-10
        url = f"https://{base_url}/admin/level-skills/import"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, files=file)
        error_msg = "批量导入学习技能"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def create_course_tag(self, authorization, file=None, DeviceType="web", code=200, **kwargs):
        """
        创建课程用户标签
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-11
        url = f"https://{base_url}/admin/course/tag/create"
        payload = {
            "name": '',
            "multilingualKey": "tag.reading",
            "tagType": 'normal', # 必填，可选值包括 normal、hot、recommended_search 等。
            "status": 1,
            "skillIds": [], # 关联的课程等级技能 ID 列表，Long 数组，可选，默认空数组。
        }
        payload = json.dumps(self.request_body(payload, **kwargs))
        file.update({'data': (None, payload, "application/json")})
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, files=file)
        error_msg = "创建课程用户标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def update_course_tag(self, authorization, tagId=0, DeviceType="web", code=200, **kwargs):
        """
        更新课程用户标签
        :param tagId: (integer, path, required) 标签ID
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-11
        url = f"https://{base_url}/admin/course/tag/{tagId}"
        payload = {
          "name": "string",
          "status": 0
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新课程用户标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def delete_course_tag(self, authorization, tagId=0, DeviceType="web", code=200, **kwargs):
        """
        删除课程用户标签
        :param tagId: (integer, path, required) 标签ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-11
        url = f"https://{base_url}/admin/course/tag/{tagId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除课程用户标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def course_tag_list(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        分页查询课程用户标签列表
        :param name: (string, query, optional) 名称搜索（支持标签名称和多语言key）
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :param status: (integer, query, optional) 状态过滤：0-不生效，1-生效中
        :param tagType: (string, query, optional) 标签类型过滤：normal-普通标签，hot-热门标签，recommended_search-推荐搜索标签
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-11
        url = f"https://{base_url}/admin/course/tag/list"
        payload = {
            "name": '',
            "page": 0,
            "size": 20,
            "status": 1,
            "tagType": ''
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "分页查询课程用户标签列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

