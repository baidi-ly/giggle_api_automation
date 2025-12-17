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

    def create_course_tag(self, authorization, file=None, DeviceType="web", code=200, **kwargs):
        """
        创建课程用户标签
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-11
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
        # Create Data:  V1.21.0  &  2025-11-11
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
        # Create Data:  V1.21.0  &  2025-11-11
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
        # Create Data:  V1.21.0  &  2025-11-11
        url = f"https://{base_url}/admin/course/tag/list"
        payload = {
            "page": 0,
            "size": 100,
            "status": 1,
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

    def course_album_create(self, authorization, name='', tagIds=[], DeviceType="web", code=200, **kwargs):
        """
        创建课程专辑
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-17
        url = f"https://{base_url}/admin/course/album/create"
        payload = {
            "name": name,
            "multilingualKey": "en",
            "tagIds": tagIds,
            "status": 1
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建课程专辑"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def course_album_list(self, authorization, name='', page=0, size=20, status=1, DeviceType="web", code=200, **kwargs):
        """
        分页查询课程专辑列表
        :param name: (string, query, optional) 名称搜索（支持专辑名称和多语言key）
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :param status: (integer, query, optional) 状态过滤：0-不生效，1-生效中
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-17
        url = f"https://{base_url}/admin/course/album/list"
        payload = {
            "name": name,
            "page": page,
            "size": size,
            "status": status
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "分页查询课程专辑列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def update_course_album(self, authorization, albumId, album_name, status=1, DeviceType="web", code=200):
        """
        更新课程专辑
        :param albumId: (integer, path, required) 专辑ID
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-17
        url = f"https://{base_url}/admin/course/album/{albumId}"
        payload = {
            "name": album_name,
            "status": status
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("PUT", url, headers=headers, json=payload)
        error_msg = "更新课程专辑"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def delete_course_album(self, authorization, albumId, DeviceType="web", code=200):
        """
        删除课程专辑
        :param albumId: (integer, path, required) 专辑ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-17
        url = f"https://{base_url}/admin/course/album/{albumId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除课程专辑"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getByCourseIds(self, authorization, courseIds, DeviceType="web", code=200):
        """
        根据课程ID查询课程等级技能列表
        :param courseIds: (string, query, required) 课程ID列表（多个ID用逗号分隔）
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-17
        url = f"https://{base_url}/admin/course/skill/by-course-ids"
        payload = {
            "courseIds": courseIds
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据课程ID查询课程等级技能列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def course_skill_list(self, authorization, page=0, size=20, skill='', DeviceType="web", code=200):
        """
        分页查询课程等级技能列表
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :param skill: (string, query, optional) 技能名称搜索
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-17
        url = f"https://{base_url}/admin/course/skill/list"
        payload = {
            "page": page,
            "size": size,
            "skill": skill
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

    def update(self, authorization, categoryId=0, courseCover='', courseType=0, difficulty='', educationType='', extraInfo='', eyfs='', formality='', icon='', id=0, interactionTypes='', maxAge=0, minAge=0, name='', promotionCopy='', purpose='', skills='', tag='', target='', theme='', unit=0, file=None, DeviceType="web", code=200, **kwargs):
        """
        修改一个课程
        :param categoryId: (integer, query, optional) categoryId
        :param courseCover: (string, query, optional) courseCover
        :param courseType: (integer, query, optional) courseType
        :param difficulty: (string, query, optional) difficulty
        :param educationType: (string, query, optional) educationType
        :param extraInfo: (string, query, optional) extraInfo
        :param eyfs: (string, query, optional) eyfs
        :param formality: (string, query, optional) formality
        :param icon: (string, query, optional) icon
        :param id: (integer, query, optional) id
        :param interactionTypes: (string, query, optional) interactionTypes
        :param maxAge: (integer, query, optional) maxAge
        :param minAge: (integer, query, optional) minAge
        :param name: (string, query, optional) name
        :param promotionCopy: (string, query, optional) promotionCopy
        :param purpose: (string, query, optional) purpose
        :param skills: (string, query, optional) skills
        :param tag: (string, query, optional) tag
        :param target: (string, query, optional) target
        :param theme: (string, query, optional) theme
        :param unit: (integer, query, optional) unit
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-20
        url = f"https://{base_url}/admin/course/update"
        payload = {
            "categoryId": categoryId,
            "courseCover": courseCover,
            "courseType": courseType,
            "difficulty": difficulty,
            "educationType": educationType,
            "extraInfo": extraInfo,
            "eyfs": eyfs,
            "formality": formality,
            "icon": icon,
            "id": id,
            "interactionTypes": interactionTypes,
            "maxAge": maxAge,
            "minAge": minAge,
            "name": name,
            "promotionCopy": promotionCopy,
            "purpose": purpose,
            "skills": skills,
            "tag": tag,
            "target": target,
            "theme": theme,
            "unit": unit
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, data=payload, files=file)
        error_msg = "修改一个课程"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def course_details(self, authorization, courseId, DeviceType="web", code=200):
        """
        获取课程详情包括版本信息
        :param courseId: (integer, query, required) courseId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-25
        url = f"https://{admin_base_url}/admin/course/detail"
        payload = {
            "courseId": courseId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取课程详情包括版本信息"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getAllsubcategory(self, authorization, parentId=0, DeviceType="web", code=200, **kwargs):
        """
        获取课程子目录列表
        :param parentId: (integer, query, required) parentId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-25
        url = f"https://{admin_base_url}/admin/course/series/allSubCategory"
        payload = {
            "parentId": parentId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取课程子目录列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getAlltopcategory(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取顶层课程目录列表

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-25
        url = f"https://{admin_base_url}/admin/course/series/allTopCategory"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取顶层课程目录列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def addCourseStrategy(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        新增策略定义
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-02
        url = f"https://{base_url}/admin/course/strategy/add"
        payload = {
            "strategyId": "default_path_v1",
            "enabled": True,
            "resetOnSegmentChange": False,
            "pattern": "A-B-C",
            "patternBehavior": "LOOP_PATTERN",
            "description": "默认课程分发策略"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "新增策略定义"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deleteCourseStrategy(self, authorization, strategy_id, DeviceType="web", code=200):
        """
        删除策略定义
        :param strategy_id: (integer, query, required) 策略ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/delete"
        payload = {
            "id": strategy_id
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "删除策略定义"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updateCourseStrategy(self, authorization, strategy_id, DeviceType="web", code=200, **kwargs):
        """
        更新策略定义
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/update"
        payload = {
            "id": strategy_id,
            "strategyId": "default_path_v1",
            "enabled": True,
            "resetOnSegmentChange": False,
            "pattern": "A-B-C",
            "patternBehavior": "LOOP_PATTERN",
            "description": "默认课程分发策略"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "更新策略定义"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def courseStrategies(self, authorization, page=0, size=100, DeviceType="web", code=200):
        """
        查询策略定义列表
        :param page: (integer, query, optional) 页码，从0开始
        :param size: (integer, query, optional) 每页数量
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/list"
        payload = {
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询策略定义列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def addStrategyRule(self, authorization, strategyId, courseIds, enabled=True, DeviceType="web", code=200):
        """
        新增课程规则
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/rule/add"
        payload = {
            "strategyId": strategyId,
            "enabled": enabled,
            "courseIds": courseIds
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "新增课程规则"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deleteStrategyRule(self, authorization, rule_id, DeviceType="web", code=200):
        """
        删除课程规则
        :param id: (integer, query, required) 规则ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/rule/delete"
        payload = {
            "id": rule_id
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "删除课程规则"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def strategyRules(self, authorization, page=0, size=100, DeviceType="web", code=200):
        """
        查询课程规则列表
        :param page: (integer, query, optional) 页码，从0开始
        :param size: (integer, query, optional) 每页数量
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/rule/list"
        payload = {
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询课程规则列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updateStrategyRule(self, authorization, id, strategyId, courseIds, enabled=True, DeviceType="web", code=200):
        """
        更新课程规则
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/rule/update"
        payload = {
            "id": id,
            "strategyId": strategyId,
            "enabled": enabled,
            "courseIds": courseIds
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "更新课程规则"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def addStrategylevelRule(self, authorization, strategyId, level, DeviceType="web", code=200):
        """
        新增等级策略
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/level-rule/add"
        payload = {
            "strategyId": strategyId,
            "level": level
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "新增等级策略"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deleteStrategylevelRule(self, authorization, id=0, DeviceType="web", code=200, **kwargs):
        """
        删除等级策略
        :param id: (integer, query, required) 策略ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/level-rule/delete"
        payload = {
            "id": id
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "删除等级策略"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def strategylevelRules(self, authorization, page=0, size=100, DeviceType="web", code=200, **kwargs):
        """
        查询等级策略列表
        :param page: (integer, query, optional) 页码，从0开始
        :param size: (integer, query, optional) 每页数量
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/level-rule/list"
        payload = {
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询等级策略列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updateStrategylevelRule(self, authorization, level_rule_id, strategyId, level, DeviceType="web", code=200):
        """
        更新等级策略
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/level-rule/update"
        payload = {
            "id": level_rule_id,
            "strategyId": strategyId,
            "level": level
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "更新等级策略"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def strategy_preview(self, authorization, DeviceType="web", code=200):
        """
        预览当前草稿配置
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/preview"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "预览当前草稿配置"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def publish_strategy(self, authorization, DeviceType="web", code=200):
        """
        发布配置
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/publish"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "发布配置"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def strategy_history_detail(self, authorization, id=0, DeviceType="web", code=200):
        """
        查询发布历史详情
        :param id: (integer, query, required) 历史记录ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/history/detail"
        payload = {
            "id": id
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询发布历史详情"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def strategy_historys(self, authorization, page=0, size=10, DeviceType="web", code=200, **kwargs):
        """
        查询发布历史列表
        :param page: (integer, query, optional) 页码，从0开始
        :param size: (integer, query, optional) 每页数量
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/strategy/history/list"
        payload = {
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询发布历史列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def addVoiceMultilingual(self, authorization, courseId, DeviceType="web", code=200, **kwargs):
        """
        新增语音文案
        courseId + key + targetLanguage 组合不与现有重复
        :param Long: (Long, required) 必填：课程ID
        :param String: (String, required) 必填：环节标识（比如某一页、某一步骤的key）
        :param String: (String, required) 必填：英文原文文案
        :param String: (String, required) 必填：目标语言代码（如 "en"、"ar"）
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/voice/multilingual/add"
        payload = {
            "courseId": courseId,          # Long，必填：课程ID
            "key": "intro",           # String，必填：环节标识（比如某一页、某一步骤的key）
            "englishText": "Hello",   # String，必填：英文原文文案
            "targetLanguage": "en"    # String，必填：目标语言代码（如 "en"、"ar"）
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "新增语音文案"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deleteVoiceMultilingual(self, authorization, id, DeviceType="web", code=200):
        """
        删除语音文案
        :param id: (integer, path, required) 记录ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/voice/multilingual/delete/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除语音文案"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updateVoiceMultilingual(self, authorization, id, translatedText, DeviceType="web", code=200):
        """
        更新语音文案
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/voice/multilingual/update"
        payload = {
            "id": id,
            "translatedText": translatedText
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "更新语音文案"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def voiceMultilinguals(self, authorization, courseId, DeviceType="web", code=200, **kwargs):
        """
        分页查询语音文案列表
        :param audioStatus: (integer, query, optional) 音频状态
        :param courseId: (integer, query, optional) 课程ID
        :param key: (string, query, optional) 环节标识
        :param page: (integer, query, optional) 页码，从0开始
        :param size: (integer, query, optional) 每页数量
        :param targetLanguage: (string, query, optional) 目标语言
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/voice/multilingual/list"
        payload = {
            "audioStatus": 0,
            "courseId": courseId,
            "key": '',
            "page": 0,
            "size": 10,
            "targetLanguage": 'en'
        }
        payload = self.request_body(payload)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "分页查询语音文案列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def batchImportMultilingual(self, authorization, items, DeviceType="web", code=200):
        """
        批量导入语音文案
        :param items: (array, body, required) items
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/voice/multilingual/batchImport"
        payload = {"items": items}
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "批量导入语音文案"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def regenerateMultilingual(self, authorization, id, DeviceType="web", code=200):
        """
        重新生成语音
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/admin/course/voice/multilingual/regenerate"
        payload = {
            "id": id
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "重新生成语音"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getCourseWords(self, authorization, courseId, DeviceType="web"):
        """
        搜索课程单词列表
        :param keyword: (string, query, optional) keyword
        :param page: (integer, query, optional) page
        :param size: (integer, query, optional) size
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-17
        url = f"https://{base_url}/admin/course/{courseId}/words"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "搜索课程单词列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response