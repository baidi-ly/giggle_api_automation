import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class AdminCurriculumApi(BaseAPI):
    """后台课程路径接口"""

    def create_curriculum_path(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        创建课程路径
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/admin/curriculum/path/create"
        payload = {
            "pathName": "pathName",
            "regionPolicy": "US",
            "status": 0
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建课程路径"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def curriculum_path_list(self, authorization, DeviceType="web", code=200):
        """
        查询路径列表

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/admin/curriculum/path/list"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询路径列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def update_curriculum_path(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        更新课程路径
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/admin/curriculum/path/update"
        payload = {
            "id": 0,
            "pathName": "string",
            "regionPolicy": "string",
            "status": 0
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "更新课程路径"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def delete_curriculum_path(self, authorization, id, DeviceType="web", code=200):
        """
        删除课程路径
        :param id: (integer, path, required) 路径ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/admin/curriculum/path/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除课程路径"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def create_curriculum_level(self, authorization, pathId, DeviceType="web", **kwargs):
        """
        创建课程等级
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/admin/curriculum/level/create"
        payload = {
            "pathId": pathId,
            "levelNum": 2,
            "levelName": "Level 2",
            "goalTitle": "",
            "goalContent": ""
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建课程等级"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def curriculum_level_list(self, authorization, pathId, DeviceType="web", code=200):
        """
        获取路径下Level列表
        :param pathId: (integer, query, required) 路径ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/admin/curriculum/level/list"
        payload = {
            "pathId": pathId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取路径下Level列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def update_curriculum_level(self, authorization, level_id, DeviceType="web", **kwargs):
        """
        更新课程等级
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/admin/curriculum/level/update"
        payload = {
            "id": level_id,
            "levelName": "Level 1",
            "goalTitle": "",
            "goalContent": ""
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "更新课程等级"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def delete_curriculum_level(self, authorization, id, DeviceType="web"):
        """
        删除课程等级
        :param id: (integer, path, required) 等级ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/admin/curriculum/level/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除课程等级"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def level_details(self, authorization, levelId=0, DeviceType="web", code=200):
        """
        删除课程等级
        :param id: (integer, path, required) 等级ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/api/curriculum/levels/{levelId}/contents"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除课程等级"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def create_curriculum_unit(self, authorization, levelId, unitNum=1, unitName='Unit 1', PhonicsContent='',
                               VocabularyContent='', GrammarContent='', status=1, DeviceType="web"):
        """
        创建课程单元
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/admin/curriculum/unit/create"
        payload = {
            "levelId": levelId,
            "unitNum": unitNum,
            "unitName": unitName,
            "unitGoals": [
                {
                    "goalTitle": "Phonics",
                    "goalContent": PhonicsContent
                },
                {
                    "goalTitle": "Vocabulary",
                    "goalContent": VocabularyContent
                },
                {
                    "goalTitle": "Grammar",
                    "goalContent": GrammarContent
                }
            ],
            "status": status
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建课程单元"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def curriculum_unit_list(self, authorization, levelId, DeviceType="web"):
        """
        获取等级下Unit列表
        :param levelId: (integer, query, required) 等级ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/admin/curriculum/unit/list"
        payload = {
            "levelId": levelId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取等级下Unit列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_curriculum_unit(self, authorization, unitId, unitNum=1, unitName='Unit 1', PhonicsContent='',
                               VocabularyContent='', GrammarContent='', status=1, DeviceType="web"):
        """
        更新课程单元
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/admin/curriculum/unit/update"
        payload = {
            "id": unitId,
            "unitNum": unitNum,
            "unitName": unitName,
            "unitGoals": [
                {
                    "goalTitle": "Phonics",
                    "goalContent": PhonicsContent
                },
                {
                    "goalTitle": "Vocabulary",
                    "goalContent": VocabularyContent
                },
                {
                    "goalTitle": "Grammar",
                    "goalContent": GrammarContent
                }
            ],
            "status": status
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "更新课程单元"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def delete_curriculum_unit(self, authorization, unitId, DeviceType="web"):
        """
        删除课程单元
        :param id: (integer, path, required) 单元ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.23.0  &  2025-12-23
        url = f"https://{base_url}/admin/curriculum/unit/{unitId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除课程单元"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

