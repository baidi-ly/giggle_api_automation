import datetime
import sys
import os
from time import strftime

import pandas as pd
from pandas import DataFrame

import config
from test_case.page_api.admin.admin_course_api import AdminCourseApi
from test_case.page_api.admin.admin_levelskills_api import AdminLevelskillsApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.Admin
@pytest.mark.AdminCourse
class TestAdminCourse:

    def setup_class(self):
        self.admin = AdminCourseApi()
        self.admin_levelskills = AdminLevelskillsApi()
        self.authorization = self.admin.get_authorization()[0]
        self.admin_authorization = self.admin.get_admin_authorization()[0]
        self.now = strftime("%Y%m%d%H%M%S")

    def teardown_class(self):
        '''后置清除等级技能'''
        try:
            # 获取所有教育类型为dibo_test开头的等级技能
            delete_skills = []
            course_skills3 = self.admin_levelskills.course_skills(self.authorization)['data']['content']
            for course_skill in course_skills3:
                if course_skill['educationType'].startswith('dibo_test'):
                    delete_skills.append(course_skill['id'])
            # 删除等级技能
            if delete_skills:
                del_res = self.admin_levelskills.deleteLevelskills(self.authorization, delete_skills)
                assert del_res['code'] == 200
        except Exception as e:
            print(f'删除等级技能失败，原因是：{e}')

        try:
            for status in [0, 1]:
                pl = {"status": status}
                course_tags = self.admin.course_tag_list(self.authorization, **pl)['data']
                for course_tag in course_tags:
                    # 删除课程用户标签
                    if course_tag['name'].startswith('course_tag_test'):
                        course_tag_id = course_tag['id']
                        delete_res = self.admin.delete_course_tag(self.authorization, course_tag_id)
                        assert delete_res['data'] == '删除成功', f"接口返回data数据异常：{delete_res['data']}"
        except Exception as e:
            print(f'删除课程用户标签失败，原因是：{e}')

        try:
            # 删除状态为生效的课程专辑
            album_res1 = self.admin.course_album_list(self.authorization)['data']['content']
            for album in album_res1:
                if album['name'].startswith('dibo_test'):
                    album_id = album['id']
                    # 删除课程专辑
                    delete_res = self.admin.delete_course_album(self.authorization, album_id)
                    assert delete_res['data'] == "删除成功", f"接口返回data数据异常：{delete_res['data']}"
            # 删除状态为废弃的课程专辑
            album_res2 = self.admin.course_album_list(self.authorization, status=0)['data']['content']
            for album in album_res2:
                if album['name'].startswith('dibo_test'):
                    album_id = album['id']
                    # 删除课程专辑
                    delete_res = self.admin.delete_course_album(self.authorization, album_id)
                    assert delete_res['data'] == "删除成功", f"接口返回data数据异常：{delete_res['data']}"
        except Exception as e:
            print(f'删除课程专辑失败，原因是：{e}')

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
            if course['name'] == 'dibo_test':
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

    @pytest.fixture(scope='function')
    def createLevelSkill_method(self):
        '''方法固件 - 创建多个等级技能'''
        skillIds = []
        for i in range(3):
            educationType = "dibo_test" + self.now + str(i)
            pl = {
                "educationType": educationType,
            }
            skill_id = self.admin_levelskills.createLevelSkill(self.authorization, **pl)['data']['id']
            skillIds.append(skill_id)

        yield skillIds

        # 删除等级技能
        del_res = self.admin_levelskills.deleteLevelskills(self.authorization, skillIds)
        assert del_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{del_res['code']}】"

    @pytest.fixture(scope='function')
    def createCourseTag_method(self):
        '''方法固件 - 创建课程用户标签'''
        skillIds = []
        for i in range(3):
            educationType = "dibo_test" + self.now + str(i)
            pl = {
                "educationType": educationType,
            }
            skill_id = self.admin_levelskills.createLevelSkill(self.authorization, **pl)['data']['id']
            skillIds.append(skill_id)

        # 创建课程用户标签
        tag_name = 'course_tag_test' + self.now
        pl = {
            "name": tag_name,
            "multilingualKey": "tag.reading",
            "tagType": 'normal', # 必填，可选值包括 normal、hot、recommended_search 等。
            "status": 1,
            "skillIds": skillIds, # 关联的课程等级技能 ID 列表，Long 数组，可选，默认空数组。
        }

        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + f'/test_data/story_face.webp', 'rb'))
        }
        res = self.admin.create_course_tag(self.authorization, file=file, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        course_tag_id = res['data']['id']

        yield course_tag_id

        # 删除课程标签
        res = self.admin.delete_course_tag(self.authorization, course_tag_id)
        assert res['code'] == 200, f"删除课程标签失败！"

    @pytest.mark.release
    def test_admin_course_positive_create_course_tag_ok(self, createLevelSkill_method):
        """创建课程用户标签-正向用例"""
        # 创建多个等级技能
        skillIds = createLevelSkill_method
        # 创建课程用户标签
        tag_name = 'course_tag_test' + self.now
        pl = {
            "name": tag_name,
            "multilingualKey": "tag.reading",
            "tagType": 'normal', # 必填，可选值包括 normal、hot、recommended_search 等。
            "status": 1,
            "skillIds": skillIds, # 关联的课程等级技能 ID 列表，Long 数组，可选，默认空数组。
        }

        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + f'/test_data/story_face.webp', 'rb'))
        }
        res = self.admin.create_course_tag(self.authorization, file=file, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['id'], f"接口返回data数据异常：{res['data']}"

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
    def test_admin_course_permission_create_course_tag(self, desc, value):
        """创建课程用户标签-权限测试"""
        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + f'/test_data/story_face.webp', 'rb'))
        }
        res = self.admin.create_course_tag(value, file=file, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_positive_update_course_tag_ok(self, createLevelSkill_method):
        """更新课程用户标签-正向用例"""
        # 创建多个等级技能
        skillIds = createLevelSkill_method
        # 创建课程用户标签
        tag_name = 'course_tag_test' + self.now
        pl = {
            "name": tag_name,
            "multilingualKey": "tag.reading",
            "tagType": 'normal', # 必填，可选值包括 normal、hot、recommended_search 等。
            "status": 1,
            "skillIds": skillIds, # 关联的课程等级技能 ID 列表，Long 数组，可选，默认空数组。
        }

        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + f'/test_data/story_face.webp', 'rb'))
        }
        create_res = self.admin.create_course_tag(self.authorization, file=file, **pl)
        course_tag_id = create_res['data']['id']    # 用户标签ID
        # 更新课程用户标签
        tag_name_new = 'course_tag_test_new' + self.now
        pl1 = {
            "name": tag_name_new,
            "status": 0
        }
        update_res = self.admin.update_course_tag(self.authorization, course_tag_id, **pl1)
        assert isinstance(update_res, dict), f'接口返回类型异常: {type(update_res)}'
        assert update_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{update_res['code']}】"
        assert update_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{update_res['message']}】"
        assert update_res['data']['id'] == course_tag_id, f"接口返回data数据异常：{update_res['data']}"

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
    def test_admin_course_permission_update_course_tag(self, desc, value):
        """更新课程用户标签-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.update_course_tag(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_positive_delete_course_tag_ok(self, createLevelSkill_method):
        """删除课程用户标签-正向用例"""
        # 创建多个等级技能
        skillIds = createLevelSkill_method
        # 创建课程用户标签
        tag_name = 'course_tag_test' + self.now
        pl = {
            "name": tag_name,
            "multilingualKey": "tag.reading",
            "tagType": 'normal', # 必填，可选值包括 normal、hot、recommended_search 等。
            "status": 1,
            "skillIds": skillIds, # 关联的课程等级技能 ID 列表，Long 数组，可选，默认空数组。
        }

        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + f'/test_data/story_face.webp', 'rb'))
        }
        create_res = self.admin.create_course_tag(self.authorization, file=file, **pl)
        course_tag_id = create_res['data']['id']    # 用户标签ID
        # 删除课程用户标签
        res = self.admin.delete_course_tag(self.authorization, course_tag_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == '删除成功', f"接口返回data数据异常：{res['data']}"

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
    def test_admin_course_permission_delete_course_tag(self, desc, value):
        """删除课程用户标签-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.delete_course_tag(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_positive_course_tags_ok(self):
        """分页查询课程用户标签列表-正向用例"""
        res = self.admin.course_tag_list(self.authorization)
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
    def test_admin_course_permission_course_tags(self, desc, value):
        """分页查询课程用户标签列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.course_tag_list(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_createCourseTag_total_ok(self, createLevelSkill_method):
        """创建课程用户标签-正向用例"""
        # 创建多个等级技能
        skillIds = createLevelSkill_method
        # 创建课程用户标签
        tag_name = 'course_tag_test' + self.now
        pl = {
            "name": tag_name,
            "multilingualKey": "tag.reading",
            "tagType": 'normal', # 必填，可选值包括 normal、hot、recommended_search 等。
            "status": 1,
            "skillIds": skillIds, # 关联的课程等级技能 ID 列表，Long 数组，可选，默认空数组。
        }

        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + f'/test_data/story_face.webp', 'rb'))
        }
        create_res = self.admin.create_course_tag(self.authorization, file=file, **pl)
        assert isinstance(create_res, dict), f'接口返回类型异常: {type(create_res)}'
        assert create_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{create_res['code']}】"
        course_tag_id = create_res['data']['id']
        pl1 = {
            "name": '',
            "status": 1
        }
        course_tags1 = self.admin.course_tag_list(self.authorization, **pl1)['data']['content']
        for course_tag in course_tags1:
            if course_tag['id'] == course_tag_id:
                assert course_tag['status'] == pl.get('status')
                assert course_tag['name'] == pl.get('name')
                assert course_tag['multilingualKey'] == pl.get('multilingualKey')
                skills = [int(i) for i in DataFrame(course_tag['skills'])['id'].tolist()]
                assert skills == pl.get('skillIds')
                break
        else:
            assert False, "新增课程用户标签后，在查询的课程用户标签列表中未查询到结果！"

        # 更新课程用户标签
        tag_name_new = 'course_tag_test_new' + self.now
        pl2 = {
            "name": tag_name_new,
            "status": 0
        }
        update_res = self.admin.update_course_tag(self.authorization, course_tag_id, **pl1)
        assert update_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{update_res['code']}】"
        pl3 = {
            "name": '',
            "status": 0
        }
        course_tags2 = self.admin.course_tag_list(self.authorization, **pl3)['data']['content']
        for course_tag in course_tags2:
            if course_tag['id'] == course_tag_id:
                assert course_tag['status'] == pl2.get('status')
                assert course_tag['name'] == pl2.get('name')
                assert course_tag['multilingualKey'] == pl.get('multilingualKey')
                skills = [int(i) for i in DataFrame(course_tag['skills'])['id'].tolist()]
                assert skills == pl2.get('skillIds')
                break
        else:
            assert False, "新增课程用户标签后，在查询的课程用户标签列表中未查询到结果！"

        # 删除课程用户标签
        delete_res = self.admin.delete_course_tag(self.authorization, course_tag_id)
        assert delete_res['data'] == '删除成功', f"接口返回data数据异常：{delete_res['data']}"
        course_tags3 = self.admin.course_tag_list(self.authorization, **pl3)['data']
        course_tag_ids3 = DataFrame(course_tags3)['id'].tolist()
        assert course_tag_id not in course_tag_ids3

    @pytest.mark.release
    def test_admin_course_positive_album_create_ok(self, createCourseTag_method):
        """创建课程专辑-正向用例"""
        tagIds = [createCourseTag_method]
        album_name = 'dibo_test' + self.now
        res = self.admin.course_album_create(self.authorization, album_name, tagIds)
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
    def test_admin_course_permission_album_create(self, desc, value):
        """创建课程专辑-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.course_album_create(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_positive_albums_ok(self):
        """分页查询课程专辑列表-正向用例"""
        res = self.admin.course_album_list(self.authorization)
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
    def test_admin_course_permission_albums(self, desc, value):
        """分页查询课程专辑列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.course_album_list(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_positive_update_album_ok(self, createCourseTag_method):
        """更新课程专辑-正向用例"""
        # 创建课程专辑
        tagIds = [createCourseTag_method]
        album_name = 'dibo_test' + self.now
        res = self.admin.course_album_create(self.authorization, album_name, tagIds)
        album_id = res['data']['id']

        # 更新课程专辑
        album_new_name = 'dibo_test_new' + self.now
        res = self.admin.update_course_album(self.authorization, album_id, album_new_name, status=0)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['id'] == album_id, f"接口返回data数据异常：{res['data']}"

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
    def test_admin_course_permission_update_album(self, desc, value):
        """更新课程专辑-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.update_course_album(value, 0, '', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_positive_delete_album_ok(self, createCourseTag_method):
        """删除课程专辑-正向用例"""
        # 创建课程专辑
        tagIds = [createCourseTag_method]
        album_name = 'dibo_test' + self.now
        res = self.admin.course_album_create(self.authorization, album_name, tagIds)
        album_id = res['data']['id']

        # 删除课程专辑
        res = self.admin.delete_course_album(self.authorization, album_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == "删除成功", f"接口返回data数据异常：{res['data']}"

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
    def test_admin_course_permission_delete_album(self, desc, value):
        """删除课程专辑-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.delete_course_album(value, 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_album_ok(self, createCourseTag_method):
        """课程专辑-增删改查测试"""

        # 创建课程专辑
        tagIds = [createCourseTag_method]
        album_name = 'dibo_test' + self.now
        create_res = self.admin.course_album_create(self.authorization, album_name, tagIds)
        album_id = create_res['data']['id']

        # 分页查询课程专辑列表，验证创建课程专辑成功
        album_res1 = self.admin.course_album_list(self.authorization)['data']['content']
        for album in album_res1:
            if album['id'] == album_id:
                assert album['name'] == album_name
                assert album['multilingualKey'] == 'en'
                assert album['status'] == 1
                break
        else:
            assert False, "创建课程专辑失败！"

        # 更新课程专辑
        album_new_name = 'dibo_test_new' + self.now
        update_res = self.admin.update_course_album(self.authorization, album_id, album_new_name, status=0)
        assert update_res['data']['id'] == album_id, f"接口返回data数据异常：{update_res['data']}"

        # 更新课程专辑后分页查询课程专辑列表，验证更新课程专辑成功
        album_res2 = self.admin.course_album_list(self.authorization, status=0)['data']['content']
        for album in album_res2:
            if album['id'] == album_id:
                assert album['name'] == album_new_name
                assert album['multilingualKey'] == 'en'
                assert album['status'] == 0
                break
        else:
            assert False, "更新课程专辑失败！"

        # 删除课程专辑
        delete_res = self.admin.delete_course_album(self.authorization, album_id)
        assert delete_res['data'] == "删除成功", f"接口返回data数据异常：{delete_res['data']}"

        # 删除课程专辑后分页查询状态为生效的课程专辑列表，验证删除课程专辑成功
        album_res3_0 = self.admin.course_album_list(self.authorization)['data']['content']
        album_ids = DataFrame(album_res3_0, columns=['id', 'name', 'tagIds'])['id'].tolist()
        assert album_id not in album_ids, "删除课程专辑失败"

        # 删除课程专辑后分页状态为废弃的查询课程专辑列表，验证删除课程专辑成功
        album_res3_1 = self.admin.course_album_list(self.authorization, status=0)['data']['content']
        album_ids = DataFrame(album_res3_1, columns=['id', 'name', 'tagIds'])['id'].tolist()
        assert album_id not in album_ids, "删除课程专辑失败"

    @pytest.mark.release
    def test_admin_course_positive_getByCourseIds_ok(self):
        """根据课程ID查询课程等级技能列表-正向用例"""
        courseIds = self.admin.course_listAll(self.admin_authorization, 641364208128069)['data'][0]['id']
        res = self.admin.getByCourseIds(self.authorization, courseIds)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'][0]['courseId'] == courseIds, f"接口返回data数据异常：{res['data']}"
        skills_res = res['data'][0]['skills']
        for skill in skills_res:
            assert skill['educationType'] == 'Listening and Speaking Skills'
            assert skill['learningLevel'] == 'L5'
            assert skill['prerequisiteSkill'] == None

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
    def test_admin_course_permission_getByCourseIds(self, desc, value):
        """根据课程ID查询课程等级技能列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.getByCourseIds(value, '', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_positive_course_skills_ok(self):
        """分页查询课程等级技能列表-正向用例"""
        res = self.admin.course_skill_list(self.authorization)
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
    def test_admin_course_permission_course_skills(self, desc, value):
        """分页查询课程等级技能列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.course_skill_list(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"