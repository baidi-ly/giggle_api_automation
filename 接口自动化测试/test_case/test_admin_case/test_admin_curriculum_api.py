import sys
import os
from time import strftime

from pandas import DataFrame

from test_case.page_api.admin.admin_course_api import AdminCourseApi
from test_case.page_api.admin.admin_curriculum_api import AdminCurriculumApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.admin
@pytest.mark.adminCurriculum
class TestAdminCurriculum:

    def setup_class(self):
        self.admin_curriculum = AdminCurriculumApi()
        self.authorization = self.admin_curriculum.get_authorization()[0]
        self.admin_auth = self.admin_curriculum.get_admin_authorization()[0]

        self.now = strftime("%Y%m%d%H%M%S")

    def teardown_class(self):

        # 更新课程路径后，查询路径列表，验证更新成功
        list_res3 = self.admin_curriculum.curriculum_path_list(self.admin_auth)['data']
        for item in list_res3:
            if item['pathName'].startswith('dibo_test'):
                path_id = item['id']
                # 删除课程路径
                delete_res = self.admin_curriculum.delete_curriculum_path(self.admin_auth, path_id)
                assert delete_res['message'] == 'success'

    @pytest.fixture(scope="class")
    def create_curriculum_path_fixtures(self):
        '''创建课程路径'''
        # 创建课程路径
        pathName = 'dibo_test_curriculum_path' + self.now
        create_res = self.admin_curriculum.create_curriculum_path(self.admin_auth, pathName=pathName)
        if create_res['code'] == 100186:
            create_res = self.admin_curriculum.create_curriculum_path(self.admin_auth, pathName=pathName, regionPolicy="KR")
            path_id = create_res['data']['id']
        else:
            path_id = create_res['data']['id']

        yield path_id

        # 删除课程路径
        delete_res = self.admin_curriculum.delete_curriculum_path(self.admin_auth, path_id)
        assert delete_res['message'] == 'success'

    @pytest.fixture(scope="class")
    def create_curriculum_level_fixtures(self, create_curriculum_path_fixtures):
        '''创建课程等级'''
        # 创建课程路径
        path_id = create_curriculum_path_fixtures
        # 创建课程等级
        goalTitle = "dibo_test_curriculum_level" + self.now
        pl = {
            "levelNum": 2,
            "levelName": "Level 2",
            "goalTitle": goalTitle,
            "goalContent": ""
        }
        create_res = self.admin_curriculum.create_curriculum_level(self.admin_auth, path_id, **pl)
        level_id = create_res['data']['id']

        yield level_id

        # 删除课程等级
        delete_res = self.admin_curriculum.delete_curriculum_level(self.admin_auth, level_id)
        assert delete_res['message'] == 'success'

    @pytest.mark.smoke
    def test_admin_curriculum_positive_create_curriculum_path(self):
        """课程路径 - 增删改查校验"""
        # 创建课程路径
        pathName = 'dibo_test_curriculum_path' + self.now
        create_res = self.admin_curriculum.create_curriculum_path(self.admin_auth, pathName=pathName)
        if create_res['code'] == 100186:
            create_res = self.admin_curriculum.create_curriculum_path(self.admin_auth, pathName=pathName, regionPolicy="KR")
            path_id = create_res['data']['id']
        else:
            path_id = create_res['data']['id']
        # 创建课程路径后，查询路径列表，验证新增成功
        list_res2 = self.admin_curriculum.curriculum_path_list(self.admin_auth)['data']
        path_ids = DataFrame(list_res2)['id'].tolist()
        assert path_id in path_ids
        # 更新课程路径
        pathNameNew = 'dibo_test_curriculum_path_new' + self.now
        pl = {
            "id": path_id,
            "pathName": pathNameNew,
            "regionPolicy": "TW",
            "status": 0
        }
        update_res = self.admin_curriculum.update_curriculum_path(self.admin_auth, **pl)
        assert update_res['data']['id'] == path_id
        assert update_res['data']['pathName'] == pathNameNew
        assert update_res['data']['regionPolicy'] == "TW"
        assert update_res['data']['status'] == 0
        # 更新课程路径后，查询路径列表，验证更新成功
        list_res3 = self.admin_curriculum.curriculum_path_list(self.admin_auth)['data']
        for item in list_res3:
            if item['id'] == path_id:
                assert item['pathName'] == pathNameNew
                assert item['regionPolicy'] == "TW"
                assert item['status'] == 0
                break
        else:
            assert False
        # 删除课程路径
        delete_res = self.admin_curriculum.delete_curriculum_path(self.admin_auth, path_id)
        assert delete_res['message'] == 'success'
        # 删除课程路径后，查询路径列表，验证删除成功
        list_res4 = self.admin_curriculum.curriculum_path_list(self.admin_auth)['data']
        if list_res4:
            path_ids = DataFrame(list_res4)['id'].tolist()
            assert path_id not in path_ids

    @pytest.mark.smoke
    def test_admin_curriculum_positive_curriculum_level(self, create_curriculum_path_fixtures):
        """课程等级 - 增删改查校验"""

        path_id = create_curriculum_path_fixtures
        # 创建课程等级
        goalTitle = "dibo_test_curriculum_goal" + self.now
        pl = {
            "levelNum": 2,
            "levelName": "Level 2",
            "goalTitle": goalTitle,
            "goalContent": ""
        }
        create_res = self.admin_curriculum.create_curriculum_level(self.admin_auth, path_id, **pl)
        level_id = create_res['data']['id']
        # 创建课程等级后，查询路径列表，验证新增成功
        list_res2 = self.admin_curriculum.curriculum_level_list(self.admin_auth, path_id)['data']
        level_ids = DataFrame(list_res2)['id'].tolist()
        assert level_id in level_ids
        # 更新课程等级
        goalTitleNew = 'dibo_test_curriculum_goal_new' + self.now
        pl = {
            "levelName": "Level 1",
            "goalTitle": goalTitleNew,
            "goalContent": ""
        }
        update_res = self.admin_curriculum.update_curriculum_level(self.admin_auth, level_id, **pl)
        assert update_res['data']['id'] == level_id
        assert update_res['data']['levelName'] == "Level 1"
        assert update_res['data']['goalTitle'] == goalTitleNew
        assert update_res['data']['goalContent'] == ""
        # 更新课程等级后，查询路径列表，验证更新成功
        list_res3 = self.admin_curriculum.curriculum_level_list(self.admin_auth, path_id)['data']
        for item in list_res3:
            if item['id'] == level_id:
                assert item['goalTitle'] == goalTitleNew
                assert item['levelName'] == "Level 1"
                assert item['goalContent'] == ""
                break
        else:
            assert False
        # 删除课程等级
        delete_res = self.admin_curriculum.delete_curriculum_level(self.admin_auth, level_id)
        assert delete_res['message'] == 'success'
        # 删除课程等级后，查询路径列表，验证删除成功
        list_res4 = self.admin_curriculum.curriculum_level_list(self.admin_auth, path_id)['data']
        if list_res4:
            level_ids = DataFrame(list_res4)['id'].tolist()
            assert level_id not in level_ids

    @pytest.mark.smoke
    def test_admin_curriculum_positive_curriculum_unit(self, create_curriculum_level_fixtures):
        """课程单元 - 增删改查校验"""

        level_id = create_curriculum_level_fixtures
        # 创建课程单元
        PhonicsContent = "dibo_test_PhonicsContent" + self.now
        VocabularyContent = "dibo_test_VocabularyContent" + self.now
        GrammarContent = "dibo_test_GrammarContent" + self.now
        create_res = self.admin_curriculum.create_curriculum_unit(self.admin_auth, level_id, PhonicsContent=PhonicsContent,
                                                                  VocabularyContent=VocabularyContent, GrammarContent=GrammarContent)
        unit_id = create_res['data']['id']
        # 创建课程单元后，查询路径列表，验证新增成功
        list_res2 = self.admin_curriculum.curriculum_unit_list(self.admin_auth, level_id)['data']
        unit_ids = DataFrame(list_res2)['id'].tolist()
        assert unit_id in unit_ids
        # 更新课程单元
        PhonicsContentNew = "dibo_test_PhonicsContent" + self.now
        VocabularyContentNew = "dibo_test_VocabularyContent" + self.now
        GrammarContentNew = "dibo_test_GrammarContent" + self.now
        update_res = self.admin_curriculum.update_curriculum_unit(self.admin_auth, unit_id, PhonicsContent=PhonicsContentNew,
                                                                  VocabularyContent=VocabularyContentNew, GrammarContent=GrammarContentNew)
        assert update_res['data']['id'] == unit_id
        assert update_res['data']['unitName'] == 'Unit 1'
        assert GrammarContentNew in update_res['data']['unitGoals']
        # 更新课程单元后，查询路径列表，验证更新成功
        list_res3 = self.admin_curriculum.curriculum_unit_list(self.admin_auth, level_id)['data']
        for item in list_res3:
            if item['id'] == unit_id:
                assert item['unitName'] == 'Unit 1'
                assert GrammarContentNew in item['unitGoals']
                break
        else:
            assert False
        # 删除课程单元
        delete_res = self.admin_curriculum.delete_curriculum_unit(self.admin_auth, unit_id)
        assert delete_res['message'] == 'success'
        # 删除课程单元后，查询路径列表，验证删除成功
        list_res4 = self.admin_curriculum.curriculum_unit_list(self.admin_auth, level_id)['data']
        if list_res4:
            level_ids = DataFrame(list_res4)['id'].tolist()
            assert level_id not in level_ids