import datetime
import sys
import os
from time import strftime

import pandas as pd

import config
from test_case.page_api.admin.admin_course_api import AdminCourseApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.Admin
@pytest.mark.AdminCourse
class TestAdminCourse:

    def setup_class(self):
        self.admin = AdminCourseApi()
        self.authorization = self.admin.get_authorization()[0]
        self.admin_authorization = self.admin.get_admin_authorization()
        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.fixture(scope='class')
    def courselistAll(self):
        courselistAll = self.admin.course_listAll(self.admin_authorization, 638245113409605)
        yield courselistAll

    def test_admin_course_export_by_theme(self):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        theme = "Colors"
        export_res = self.admin.export_byTheme(self.admin_authorization, theme)
        assert export_res["data"]

    def test_admin_course_export_byTheme_notExsit(self):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        theme = "Indoor+Actions"
        export_res = self.admin.export_byTheme(self.admin_authorization, theme)
        assert not export_res["data"]

    @pytest.mark.parametrize("theme", [123, 123.4, True, "!@#~", ''],
                             ids=["integer", "float", "boolen", "special characters", 'empty'])
    def test_admin_course_export_byTheme_abnormal_character(self, theme):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        export_res = self.admin.export_byTheme(self.admin_authorization, theme)
        assert export_res["data"]

    def test_admin_course_export_byTheme_abnormal_character(self):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        theme = 'Colors'
        self.admin.export_byTheme('', theme)

    def test_admin_course_trial_list(self):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        export_res = self.admin.trial_list(self.admin_authorization)
        assert export_res["data"]

    def test_admin_course_trial_list_unauthorized(self):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        self.admin.trial_list('', code=401)

    def test_admin_course_update_to_trial(self, courselistAll):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        courseId = courselistAll['data'][0]["id"]
        export_res = self.admin.update_to_trial(self.admin_authorization, courseId)
        assert export_res["message"] == 'success'

    def test_admin_course_remove_trial(self, courselistAll):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        courseId = courselistAll['data'][0]["id"]
        export_res = self.admin.remove_trial(self.admin_authorization, courseId)
        assert export_res["message"] == 'success'

    def test_admin_course_update_blockedIds(self, courselistAll):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        courselistAll = courselistAll
        courseIds = pd.DataFrame(courselistAll['data']).loc[:, 'id'].tolist()
        export_res = self.admin.update_blockedIds(self.admin_authorization, courseIds)
        assert export_res["data"] == '更新成功'

    def test_admin_course_get_blockedIds(self, courselistAll):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        export_res = self.admin.blockedIds(self.admin_authorization)
        assert export_res["data"]['blockedIds']

    @pytest.mark.smoke
    def test_admin_course_positive_getSpelrules_ok(self):
        """获取体验课程推荐SpEL表达式规则-正向用例"""
        res = self.admin.getSpelrules(self.admin_authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_course_permission_getSpelrules(self, desc, value):
        """获取体验课程推荐SpEL表达式规则-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.getSpelrules(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 400, 100006),
            ('integer', 123, 400, 100006),
            ('float', 12.34, 400, 100006),
            ('object', {'key': 'value'}, 400, 100006),
            ('emoji', 'test_emoji', 400, 100006),
        ]
    )
    def test_admin_course_format_getSpelrules_abTest(self, desc, value, code, code_res):
        """获取体验课程推荐SpEL表达式规则-数据格式测试(abTest)"""
        try:
            res = self.admin.getSpelrules(self.admin_authorization, abTest=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('true', True, 200),
            ('false', False, 200),
        ]
    )
    def test_admin_course_boundary_getSpelrules_abTest(self, desc, value, code):
        """获取体验课程推荐SpEL表达式规则-边界值测试(abTest)"""
        res = self.admin.getSpelrules(self.admin_authorization, abTest=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_spelrules_ok(self):
        """设置体验课程推荐SpEL表达式规则-正向用例"""
        res = self.admin.spelrules(self.admin_authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_course_permission_spelrules(self, desc, value):
        """设置体验课程推荐SpEL表达式规则-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.spelrules(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_generateTags_ok(self, courselistAll):
        """AI生成课程标签-正向用例"""
        courseId = courselistAll['data']
        for course in courselistAll['data']:
            if course['name'] == 'debbie_test':
                courseId = int(course['id'])
        res = self.admin.generateTags(self.admin_authorization, 648882721525835)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_course_permission_generateTags(self, desc, value):
        """AI生成课程标签-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.generateTags(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 200),
            ('empty', "", 200),
            ('null', None, 200),
        ]
    )
    def test_admin_course_required_generateTags_courseId(self, desc, value, code):
        """AI生成课程标签-必填字段测试(courseId)"""
        if desc == 'missing':
            pl = {'pop_items': 'courseId'}
        else:
            pl = {'courseId': value}
        res = self.admin.generateTags(self.admin_authorization, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        else:
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【not found】，实际【{res['message']}】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【not found】，实际【{res['data']}】"

    @pytest.mark.release
    def test_admin_course_positive_createLevelSkill_ok(self):
        """新增等级技能-正向用例"""
        educationType = "debbie_test" + self.now
        pl = {
            "educationType": educationType,
        }
        res = self.admin.createLevelSkill(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['learningLevel'] == 'L1'
        assert res['data']['educationType'] == educationType
        assert res['data']['skill'] == 'Reading-Level1'
        assert res['data']['necessary'] == True

    @pytest.mark.release
    def test_admin_course_positive_createLevelSkill_educationType_repeat_check(self):
        """新增等级技能-验证educationType、learningLevel、skill三个参数组成唯一键，不能重复使用educationType"""
        # 验证同一个educationType第一次正常创建课程技能
        educationType = "debbie_test" + 'repeat_check' + self.now
        pl = {
            "educationType": educationType,
        }
        res1 = self.admin.createLevelSkill(self.authorization, **pl)
        assert res1['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res1['code']}】"
        # 验证同一个educationType第二次无法重复创建课程技能
        res2 = self.admin.createLevelSkill(self.authorization)
        assert isinstance(res2, dict), f'接口返回类型异常: {type(res2)}'
        assert res2['code'] == 100169, f"接口返回状态码异常: 预期【200】，实际【{res2['code']}】"
        assert res2['message'] == 'Course skill already exists', f"接口返回message信息异常: 预期【Course skill already exists】，实际【{res2['message']}】"
        assert res2['data'] == 'Course skill already exists'

    @pytest.mark.release
    @pytest.mark.parametrize('learningLevel', ["L1", "L2", "L3", "L4", "L5", "L6", "L7",
                                               "L8", "L9", "L10", "L11", "L12", "L13",
                                               "L14", "L15", "L16", "L17", "L18", "L19", "L20"])
    def test_admin_course_positive_createLevelSkill_learningLevel(self, learningLevel):
        """新增等级技能-正向用例"""
        # 新增等级技能，遍历学习等级l1-l20
        pl = {
            "learningLevel": learningLevel,
            "educationType": "debbie_test",
        }
        res = self.admin.createLevelSkill(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['learningLevel'] == learningLevel
        assert res['data']['educationType'] == "debbie_test"
        assert res['data']['skill'] == 'Reading-Level1'
        assert res['data']['necessary'] == True

    @pytest.mark.release
    def test_admin_course_positive_createLevelSkill_skill(self):
        """新增等级技能-正向用例"""
        # 新增等级技能-创建skill
        skill = "debbie_test_skill" + self.now
        pl = {
            "skill": skill,
            "educationType": "debbie_test",
        }
        res = self.admin.createLevelSkill(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['learningLevel'] == "L1"
        assert res['data']['educationType'] == "debbie_test"
        assert res['data']['skill'] == skill
        assert res['data']['necessary'] == True

    @pytest.mark.release
    def test_admin_course_positive_createLevelSkill_skill_repeat_check(self):
        """新增等级技能-正向用例"""
        # 验证同一个educationType第一次正常创建课程技能
        skill = "debbie_test_skill" + self.now
        pl = {
            "skill": skill,
            "educationType": "debbie_test",
        }
        res1 = self.admin.createLevelSkill(self.authorization, **pl)
        assert isinstance(res1, dict), f'接口返回类型异常: {type(res1)}'
        assert res1['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res1['code']}】"
        # 验证同一个educationType第二次无法重复创建课程技能
        res2 = self.admin.createLevelSkill(self.authorization)
        assert isinstance(res2, dict), f'接口返回类型异常: {type(res2)}'
        assert res2['code'] == 100169, f"接口返回状态码异常: 预期【200】，实际【{res2['code']}】"
        assert res2['message'] == 'Course skill already exists', f"接口返回message信息异常: 预期【Course skill already exists】，实际【{res2['message']}】"
        assert res2['data'] == 'Course skill already exists'

    @pytest.mark.release
    @pytest.mark.parametrize('necessary',[True, False])
    def test_admin_course_positive_createLevelSkill_necessary(self, necessary):
        """新增等级技能-正向用例"""
        educationType = "debbie_test" + self.now + str(necessary)
        pl = {
            "necessary": necessary,
            "educationType": educationType,
        }
        res = self.admin.createLevelSkill(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['data']['learningLevel'] == "L1"
        assert res['data']['educationType'] == educationType
        assert res['data']['skill'] == "Reading-Level1"
        assert res['data']['necessary'] == necessary

    @pytest.mark.release
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
        res = self.admin.createLevelSkill(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
            
    @pytest.mark.release
    def test_admin_course_positive_deleteLevelskills_ok(self):
        """批量删除等级技能-正向用例"""
        # 新增课程等级3个
        skill_ids = []
        for i in range(5):
            educationType = "debbie_test" + self.now + str(i)
            pl = {
                "educationType": educationType,
            }
            skill_id = self.admin.createLevelSkill(self.authorization, **pl)['data']['id']
            skill_ids.append(skill_id)
        # 批量删除等级技能
        res = self.admin.deleteLevelskills(self.authorization, skill_ids)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
        res = self.admin.deleteLevelskills(value, ids=[1,2,3], code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_positive_course_skills_ok(self):
        """分页查询课程等级技能列表-正向用例"""
        res = self.admin.course_skills(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_positive_levelSkills_details_ok(self):
        """更新等级技能-正向用例"""
        res = self.admin.levelSkills_details(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_course_permission_levelSkills_details(self, desc, value):
        """更新等级技能-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.levelSkills_details(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_positive_levelSkills_import_ok(self):
        """批量导入学习技能-正向用例"""
        file = {
            'file': ('批量导入技能测试文档.xlsx', open(os.getcwd() + f'/test_data/批量导入技能测试文档.xlsx', 'rb'))
        }
        res = self.admin.levelSkills_import(self.authorization, file=file)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
        res = self.admin.levelSkills_import(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"















































    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_course_permission_course_skills(self, desc, value):
        """分页查询课程等级技能列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.course_skills(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"













    @pytest.mark.release
    def test_admin_course_positive_create_ok(self):
        """创建课程用户标签-正向用例"""
        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + '/test_data/story_face.webp', 'rb'))
        }
        res = self.admin.create_course_tag(self.authorization, file=file)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize('multilingualKey',['tag.reading','tag.math',
                                                'tag.hot.example','album.math.basic','album.english.beginner'])
    def test_admin_course_positive_create_multilingualKey(self, multilingualKey):
        """创建课程用户标签-正向用例"""
        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + '/test_data/story_face.webp', 'rb'))
        }
        pl = {
            "multilingualKey":  multilingualKey
        }
        res = self.admin.create_course_tag(self.authorization, file=file, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize('tagType',['normal','hot','recommended_search'])
    def test_admin_course_positive_create_tagType(self, tagType):
        """创建课程用户标签-正向用例"""
        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + '/test_data/story_face.webp', 'rb'))
        }
        pl = {
            "tagType":  tagType
        }
        res = self.admin.create_course_tag(self.authorization, file=file, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize('status',[0, 1])
    def test_admin_course_positive_create_status(self, status):
        """创建课程用户标签-正向用例"""
        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + '/test_data/story_face.webp', 'rb'))
        }
        pl = {
            "status":  status
        }
        res = self.admin.create_course_tag(self.authorization, file=file, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize('status',[0, 1])
    def test_admin_course_positive_create_status(self, status):
        """创建课程用户标签-正向用例"""
        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + '/test_data/story_face.webp', 'rb'))
        }
        pl = {
            "status":  status
        }
        res = self.admin.create_course_tag(self.authorization, file=file, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_course_permission_create(self, desc, value):
        """创建课程用户标签-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.create_course_tag(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_positive_level_skill_list_ok(self):
        """查询等级技能列表-正向用例"""
        res = self.admin.level_skill_list(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_course_permission_level_skill_list(self, desc, value):
        """查询等级技能列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.level_skill_list(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"


