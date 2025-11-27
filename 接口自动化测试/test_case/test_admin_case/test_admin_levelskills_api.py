import datetime
import random
import string
import sys
import os
from time import strftime

from pandas import DataFrame

import config
from test_case.page_api.admin.admin_levelskills_api import AdminLevelskillsApi
from test_case.page_api.kid.kid_api import KidApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.admin
@pytest.mark.adminKid
class TestAdminkid:

    def setup_class(self):
        self.admin_levelskills = AdminLevelskillsApi()
        self.authorization = self.admin_levelskills.get_admin_authorization()[0]

        self.kid = KidApi()
        self.kid_id = self.kid.getKids(self.authorization)["data"][0]['id']

        self.now = strftime("%Y%m%d%H%M%S")

    def teardown_class(self):
        '''批量清除技能等级'''
        try:
            # 获取所有教育类型为dibo_test开头的等级技能
            delete_skills = []
            level_skills = self.admin_levelskills.level_skills(self.authorization)['data']
            for course_skill in level_skills:
                if course_skill['educationType'].startswith('dibo_test'):
                    delete_skills.append(course_skill['id'])
            # 删除等级技能
            if delete_skills:
                del_res = self.admin_levelskills.deleteLevelskills(self.authorization, delete_skills)
                assert del_res['code'] == 200
        except Exception as e:
            print(f'删除等级技能失败，原因是：{e}')
        
    @pytest.mark.smoke
    def test_admin_course_positive_createLevelSkill_ok(self):
        """新增等级技能-正向用例"""
        educationType = "dibo_test_educationType" + self.now + random.choice(string.ascii_letters)
        skill = "dibo_test_skill" + self.now
        pl = {
            "educationType": educationType,
            'skill': skill
        }
        res = self.admin_levelskills.createLevelSkill(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['learningLevel'] == 'L1'
        assert res['data']['educationType'] == educationType
        assert res['data']['skill'] == skill
        assert res['data']['necessary'] == True

    @pytest.mark.smoke
    def test_admin_course_positive_createLevelSkill_educationType_repeat_check(self):
        """新增等级技能-验证educationType、learningLevel、skill三个参数组成唯一键，不能重复使用educationType"""
        # 验证同一个educationType第一次正常创建课程技能
        educationType = "dibo_test" + 'repeat_check' + self.now
        pl = {
            "educationType": educationType,
        }
        res1 = self.admin_levelskills.createLevelSkill(self.authorization, **pl)
        assert res1['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res1['code']}】"
        # 验证同一个educationType第二次无法重复创建课程技能
        res2 = self.admin_levelskills.createLevelSkill(self.authorization)
        assert isinstance(res2, dict), f'接口返回类型异常: {type(res2)}'
        assert res2['code'] == 100169, f"接口返回状态码异常: 预期【200】，实际【{res2['code']}】"
        assert res2['message'] == 'Course skill already exists', f"接口返回message信息异常: 预期【Course skill already exists】，实际【{res2['message']}】"
        assert res2['data'] == 'Course skill already exists'

    @pytest.mark.smoke
    @pytest.mark.parametrize('learningLevel', ["L1", "L2", "L3", "L4", "L5", "L6", "L7",
                                               "L8", "L9", "L10", "L11", "L12", "L13",
                                               "L14", "L15", "L16", "L17", "L18", "L19", "L20"])
    def test_admin_course_positive_createLevelSkill_learningLevel(self, learningLevel):
        """新增等级技能-正向用例"""
        # 新增等级技能，遍历学习等级l1-l20
        pl = {
            "learningLevel": learningLevel,
            "educationType": "dibo_test" + self.now,
        }
        res = self.admin_levelskills.createLevelSkill(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['learningLevel'] == learningLevel
        assert res['data']['educationType'].startswith("dibo_test")
        assert res['data']['skill'] == 'Reading-Level1'
        assert res['data']['necessary'] == True

    @pytest.mark.smoke
    def test_admin_course_positive_createLevelSkill_skill(self):
        """新增等级技能-正向用例"""
        # 新增等级技能-创建skill
        skill = "dibo_test_skill" + self.now
        pl = {
            "skill": skill,
            "educationType": "dibo_test",
        }
        res = self.admin_levelskills.createLevelSkill(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['learningLevel'] == "L1"
        assert res['data']['educationType'] == "dibo_test"
        assert res['data']['skill'] == skill
        assert res['data']['necessary'] == True

    @pytest.mark.smoke
    def test_admin_course_positive_createLevelSkill_skill_repeat_check(self):
        """新增等级技能-正向用例"""
        # 验证同一个educationType第一次正常创建课程技能
        skill = "dibo_test_skill" + self.now + random.choice(string.ascii_letters)
        pl = {
            "skill": skill,
            "educationType": "dibo_test",
        }
        res1 = self.admin_levelskills.createLevelSkill(self.authorization, **pl)
        assert isinstance(res1, dict), f'接口返回类型异常: {type(res1)}'
        assert res1['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res1['code']}】"
        # 验证同一个educationType第二次无法重复创建课程技能
        res2 = self.admin_levelskills.createLevelSkill(self.authorization)
        assert isinstance(res2, dict), f'接口返回类型异常: {type(res2)}'
        assert res2['code'] == 100169, f"接口返回状态码异常: 预期【200】，实际【{res2['code']}】"
        assert res2['message'] == 'Course skill already exists', f"接口返回message信息异常: 预期【Course skill already exists】，实际【{res2['message']}】"
        assert res2['data'] == 'Course skill already exists'

    @pytest.mark.smoke
    @pytest.mark.parametrize('necessary',[True, False])
    def test_admin_course_positive_createLevelSkill_necessary(self, necessary):
        """新增等级技能-正向用例"""
        educationType = "dibo_test" + self.now + str(necessary)
        pl = {
            "necessary": necessary,
            "educationType": educationType,
        }
        res = self.admin_levelskills.createLevelSkill(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['data']['learningLevel'] == "L1"
        assert res['data']['educationType'] == educationType
        assert res['data']['skill'] == "Reading-Level1"
        assert res['data']['necessary'] == necessary

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_course_permission_levelSkills(self, desc, value):
        """新增等级技能-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_levelskills.createLevelSkill(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_deleteLevelskills_ok(self):
        """批量删除等级技能-正向用例"""
        # 新增课程等级3个
        skill_ids = []
        for i in range(5):
            educationType = "dibo_test" + self.now + str(i)
            pl = {
                "educationType": educationType,
            }
            skill_id = self.admin_levelskills.createLevelSkill(self.authorization, **pl)['data']['id']
            skill_ids.append(skill_id)
        # 批量删除等级技能
        res = self.admin_levelskills.deleteLevelskills(self.authorization, skill_ids)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_course_permission_deleteLevelskills(self, desc, value):
        """批量删除等级技能-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_levelskills.deleteLevelskills(value, ids=[1,2,3], code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_level_skills_ok(self):
        """分页查询课程等级技能列表-正向用例"""
        res = self.admin_levelskills.level_skills(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_update_levelSkills_ok(self):
        """更新等级技能-正向用例"""
        # 新增等级技能
        educationType = "dibo_test" + self.now + random.choice(string.ascii_letters)
        pl = {
            "educationType": educationType,
        }
        skill_id = self.admin_levelskills.createLevelSkill(self.authorization, **pl)['data']['id']
        # 分页查询课程等级技能列表，验证新增等级技能的educationType正确
        level_skills1 = self.admin_levelskills.level_skills(self.authorization)['data']
        for skill in level_skills1:
            if skill['id'] == skill_id:
                assert skill['educationType'] == educationType
                break
        else:
            assert False, "新增等级技能的educationType在列表中有误！"
        # 更新等级技能
        educationType_new = "dibo_test" + self.now + '_new'
        pl1 = {
            "educationType": educationType_new,
            "necessary": True
        }
        res = self.admin_levelskills.updateLevelSkills(self.authorization, skill_id, **pl1)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
        assert res['data']['educationType'] == educationType_new
        # 分页查询课程等级技能列表，验证更新后等级技能的educationType正确
        level_skills2 = self.admin_levelskills.level_skills(self.authorization)['data']
        for skill in level_skills2:
            if skill['id'] == skill_id:
                assert skill['educationType'] == educationType_new
                break
        else:
            assert False

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_course_permission_update_levelSkills(self, desc, value):
        """更新等级技能-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_levelskills.updateLevelSkills(value, 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_levelSkills_import_ok(self):
        """批量导入学习技能-正向用例"""
        file = {
            'file': ('学习技能导入测试(1).xlsx', open(os.getcwd() + f'/test_data/学习技能导入测试(1).xlsx', 'rb'))
        }
        res = self.admin_levelskills.levelSkills_import(self.authorization, file=file)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_levelSkills_import_abnormal(self):
        """批量导入学习技能-正向用例"""
        file = {
            'file': ('批量导入技能测试文档.xlsx', open(os.getcwd() + f'/test_data/批量导入技能测试文档.xlsx', 'rb'))
        }
        res = self.admin_levelskills.levelSkills_import(self.authorization, file=file)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == {'errors': ['第2行：教育类型缺失', '第3行：教育类型缺失', '第4行：教育类型缺失'],
                     'failed': 3,
                     'success': 0,
                     'total': 3}, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_course_permission_levelSkills_import(self, desc, value):
        """批量导入学习技能-权限测试"""
        file = {
            'file': ('批量导入技能测试文档.xlsx', open(os.getcwd() + f'/test_data/批量导入技能测试文档.xlsx', 'rb'))
        }
        res = self.admin_levelskills.levelSkills_import(value, file, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_course_level_skills_total_ok(self):
        """等级技能相关接口增删改查验证-正向用例"""
        # 新增等级技能
        educationType = "dibo_test" + self.now + random.choice(string.ascii_letters)
        pl = {
            "educationType": educationType,
        }
        skill_id = self.admin_levelskills.createLevelSkill(self.authorization, **pl)['data']['id']
        # 分页查询课程等级技能列表，验证新增等级技能的educationType正确
        level_skills1 = self.admin_levelskills.level_skills(self.authorization)['data']
        for skill in level_skills1:
            if int(skill['id']) == skill_id:
                assert skill['educationType'] == educationType
                break
        else:
            assert False, "新增等级技能后，通过分页查询课程等级技能列表，列表中未查询到新增的等级技能"
        # 更新等级技能
        educationType_new = "dibo_test" + self.now + random.choice(string.ascii_letters) + '_new'
        pl1 = {
            "educationType": educationType_new,
            "necessary": True
        }
        res = self.admin_levelskills.updateLevelSkills(self.authorization, skill_id, **pl1)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
        assert res['data']['educationType'] == educationType_new
        # 分页查询课程等级技能列表，验证更新后等级技能的educationType正确
        level_skills2 = self.admin_levelskills.level_skills(self.authorization)['data']
        for skill in level_skills2:
            if int(skill['id']) == skill_id:
                assert skill['educationType'] == educationType_new
                break
        else:
            assert False, "更新等级技能后，通过分页查询课程等级技能列表，列表中未查询到更新的等级技能"
        # 删除等级技能
        del_res = self.admin_levelskills.deleteLevelskills(self.authorization, [skill_id])
        assert del_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{del_res['code']}】"
        # 分页查询课程等级技能列表，验证删除后等级技能不存在，删除成功
        level_skills3 = self.admin_levelskills.level_skills(self.authorization)['data']
        skill_ids = DataFrame(level_skills3)['id'].tolist()
        assert str(skill_id) not in skill_ids, "删除等级技能后，通过分页查询课程等级技能列表，列表中查询到删除的等级技能"
