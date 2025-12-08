import datetime
import random
import re
import string
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
        self.admin_course = AdminCourseApi()
        self.admin_levelskills = AdminLevelskillsApi()
        self.authorization = self.admin_course.get_authorization()[0]
        self.admin_auth = self.admin_course.get_admin_authorization()[0]
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
                course_tags = self.admin_course.course_tag_list(self.authorization, **pl)['data']['content']
                for course_tag in course_tags:
                    # 删除课程用户标签
                    if course_tag['name'].startswith('course_tag_test'):
                        course_tag_id = course_tag['id']
                        if status == 1:
                            tag_id = course_tag['id']
                            pl = {
                                "name": course_tag['name'],
                                "multilingualKey": course_tag['multilingualKey'],
                                "skillIds": course_tag['skills'],
                                "status": 0
                            }
                            self.admin_course.update_course_tag(self.authorization, tag_id, **pl)
                        delete_res = self.admin_course.delete_course_tag(self.authorization, course_tag_id)
                        assert delete_res['data'] == '删除成功', f"接口返回data数据异常：{delete_res['data']}"
        except Exception as e:
            print(f'删除课程用户标签失败，原因是：{e}')

        try:
            # 删除状态为生效的课程专辑
            album_res1 = self.admin_course.course_album_list(self.authorization)['data']['content']
            for album in album_res1:
                if album['name'].startswith('dibo_test'):
                    album_id = album['id']
                    # 删除课程专辑
                    delete_res = self.admin_course.delete_course_album(self.authorization, album_id)
                    assert delete_res['data'] == "删除成功", f"接口返回data数据异常：{delete_res['data']}"
            # 删除状态为废弃的课程专辑
            album_res2 = self.admin_course.course_album_list(self.authorization, status=0)['data']['content']
            for album in album_res2:
                if album['name'].startswith('dibo_test'):
                    album_id = album['id']
                    # 删除课程专辑
                    delete_res = self.admin_course.delete_course_album(self.authorization, album_id)
                    assert delete_res['data'] == "删除成功", f"接口返回data数据异常：{delete_res['data']}"
        except Exception as e:
            print(f'删除课程专辑失败，原因是：{e}')

    @pytest.fixture(scope='class')
    def courselistAll(self):
        courselistAll = self.admin_course.course_listAll(self.admin_auth, 638245113409605)
        yield courselistAll

    def test_admin_course_export_by_theme(self):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        theme = "Colors"
        export_res = self.admin_course.export_byTheme(self.admin_auth, theme)
        assert export_res["data"]

    def test_admin_course_export_byTheme_notExsit(self):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        theme = "Indoor+Actions"
        export_res = self.admin_course.export_byTheme(self.admin_auth, theme)
        assert not export_res["data"]

    @pytest.mark.parametrize("theme", [123, 123.4, True, "!@#~", ''],
                             ids=["integer", "float", "boolen", "special characters", 'empty'])
    def test_admin_course_export_byTheme_abnormal_character(self, theme):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        export_res = self.admin_course.export_byTheme(self.admin_auth, theme)
        assert export_res["data"]

    def test_admin_course_export_byTheme_abnormal_character(self):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        theme = 'Colors'
        self.admin_course.export_byTheme('', theme)

    def test_admin_course_trial_list(self):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        export_res = self.admin_course.trial_list(self.admin_auth)
        assert export_res["data"]

    def test_admin_course_trial_list_unauthorized(self):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        self.admin_course.trial_list('', code=401)

    def test_admin_course_update_to_trial(self, courselistAll):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        courseId = courselistAll['data'][0]["id"]
        export_res = self.admin_course.update_to_trial(self.admin_auth, courseId)
        assert export_res["message"] == 'success'

    def test_admin_course_remove_trial(self, courselistAll):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        courseId = courselistAll['data'][0]["id"]
        export_res = self.admin_course.remove_trial(self.admin_auth, courseId)
        assert export_res["message"] == 'success'

    def test_admin_course_update_blockedIds(self, courselistAll):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        courselistAll = courselistAll
        courseIds = pd.DataFrame(courselistAll['data']).loc[:, 'id'].tolist()
        export_res = self.admin_course.update_blockedIds(self.admin_auth, courseIds)
        assert export_res["data"] == '更新成功'

    def test_admin_course_get_blockedIds(self, courselistAll):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        export_res = self.admin_course.blockedIds(self.admin_auth)
        assert export_res["data"]['blockedIds']

    @pytest.mark.smoke
    def test_admin_course_positive_getSpelrules_ok(self):
        """获取体验课程推荐SpEL表达式规则-正向用例"""
        res = self.admin_course.getSpelrules(self.admin_auth)
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

        res = self.admin_course.getSpelrules(value, code=401)
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
            res = self.admin_course.getSpelrules(self.admin_auth, abTest=value, code=code)
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
        res = self.admin_course.getSpelrules(self.admin_auth, abTest=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_spelrules_ok(self):
        """设置体验课程推荐SpEL表达式规则-正向用例"""
        res = self.admin_course.spelrules(self.admin_auth)
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

        res = self.admin_course.spelrules(value, code=401)
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
        res = self.admin_course.generateTags(self.admin_auth, 648882721525835)
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

        res = self.admin_course.generateTags(value, code=401)
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
        res = self.admin_course.generateTags(self.admin_auth, code=code, **pl)
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
        res = self.admin_course.create_course_tag(self.authorization, file=file, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        course_tag_id = res['data']['id']

        yield course_tag_id

        # 删除课程标签
        res = self.admin_course.delete_course_tag(self.authorization, course_tag_id)
        assert res['code'] == 200, f"删除课程标签失败！"

    @pytest.mark.smoke
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
        res = self.admin_course.create_course_tag(self.authorization, file=file, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['id'], f"接口返回data数据异常：{res['data']}"

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
    def test_admin_course_permission_create_course_tag(self, desc, value):
        """创建课程用户标签-权限测试"""
        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + f'/test_data/story_face.webp', 'rb'))
        }
        res = self.admin_course.create_course_tag(value, file=file, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
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
        create_res = self.admin_course.create_course_tag(self.authorization, file=file, **pl)
        course_tag_id = create_res['data']['id']    # 用户标签ID
        # 更新课程用户标签
        tag_name_new = 'course_tag_test_new' + self.now
        pl1 = {
            "name": tag_name_new,
            "status": 0
        }
        update_res = self.admin_course.update_course_tag(self.authorization, course_tag_id, **pl1)
        assert isinstance(update_res, dict), f'接口返回类型异常: {type(update_res)}'
        assert update_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{update_res['code']}】"
        assert update_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{update_res['message']}】"
        assert update_res['data']['id'] == course_tag_id, f"接口返回data数据异常：{update_res['data']}"

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
    def test_admin_course_permission_update_course_tag(self, desc, value):
        """更新课程用户标签-权限测试"""

        res = self.admin_course.update_course_tag(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
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
        create_res = self.admin_course.create_course_tag(self.authorization, file=file, **pl)
        course_tag_id = create_res['data']['id']    # 用户标签ID
        # 删除课程用户标签
        res = self.admin_course.delete_course_tag(self.authorization, course_tag_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == '删除成功', f"接口返回data数据异常：{res['data']}"

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
    def test_admin_course_permission_delete_course_tag(self, desc, value):
        """删除课程用户标签-权限测试"""

        res = self.admin_course.delete_course_tag(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_course_tags_ok(self):
        """分页查询课程用户标签列表-正向用例"""
        res = self.admin_course.course_tag_list(self.authorization)
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
    def test_admin_course_permission_course_tags(self, desc, value):
        """分页查询课程用户标签列表-权限测试"""

        res = self.admin_course.course_tag_list(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
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
        create_res = self.admin_course.create_course_tag(self.authorization, file=file, **pl)
        assert isinstance(create_res, dict), f'接口返回类型异常: {type(create_res)}'
        assert create_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{create_res['code']}】"
        course_tag_id = create_res['data']['id']
        pl1 = {
            "name": '',
            "status": 1
        }
        course_tags1 = self.admin_course.course_tag_list(self.authorization, **pl1)['data']['content']
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
            "status": 0,
            "multilingualKey": "tag.reading",
            "tagType": 'normal',  # 必填，可选值包括 normal、hot、recommended_search 等。
            "skillIds": skillIds,  # 关联的课程等级技能 ID 列表，Long 数组，可选，默认空数组。
        }
        update_res = self.admin_course.update_course_tag(self.authorization, course_tag_id, **pl2)
        assert update_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{update_res['code']}】"
        pl3 = {
            "name": '',
            "status": 0
        }
        course_tags2 = self.admin_course.course_tag_list(self.authorization, **pl3)['data']['content']
        for course_tag in course_tags2:
            if course_tag['id'] == course_tag_id:
                assert course_tag['status'] == pl2.get('status')
                assert course_tag['name'] == pl2.get('name')
                assert course_tag['multilingualKey'] == pl2.get('multilingualKey')
                skills = [int(i) for i in DataFrame(course_tag['skills'])['id'].tolist()]
                assert skills == pl2.get('skillIds')
                break
        else:
            assert False, "新增课程用户标签后，在查询的课程用户标签列表中未查询到结果！"

        # 删除课程用户标签
        delete_res = self.admin_course.delete_course_tag(self.authorization, course_tag_id)
        assert delete_res['data'] == '删除成功', f"接口返回data数据异常：{delete_res['data']}"
        course_tags3 = self.admin_course.course_tag_list(self.authorization, **pl3)['data']['content']
        course_tag_ids3 = DataFrame(course_tags3)['id'].tolist()
        assert course_tag_id not in course_tag_ids3

    @pytest.mark.smoke
    def test_admin_course_positive_album_create_ok(self, createCourseTag_method):
        """创建课程专辑-正向用例"""
        tagIds = [createCourseTag_method]
        album_name = 'dibo_test' + self.now
        res = self.admin_course.course_album_create(self.authorization, album_name, tagIds)
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
    def test_admin_course_permission_album_create(self, desc, value):
        """创建课程专辑-权限测试"""

        res = self.admin_course.course_album_create(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_albums_ok(self):
        """分页查询课程专辑列表-正向用例"""
        res = self.admin_course.course_album_list(self.authorization)
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
    def test_admin_course_permission_albums(self, desc, value):
        """分页查询课程专辑列表-权限测试"""

        res = self.admin_course.course_album_list(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_update_album_ok(self, createCourseTag_method):
        """更新课程专辑-正向用例"""
        # 创建课程专辑
        tagIds = [createCourseTag_method]
        album_name = 'dibo_test' + self.now + random.choice(string.ascii_letters)
        res = self.admin_course.course_album_create(self.authorization, album_name, tagIds)
        album_id = res['data']['id']

        # 更新课程专辑
        album_new_name = 'dibo_test_new' + self.now + random.choice(string.ascii_letters)
        res = self.admin_course.update_course_album(self.authorization, album_id, album_new_name, status=0)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['id'] == album_id, f"接口返回data数据异常：{res['data']}"

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
    def test_admin_course_permission_update_album(self, desc, value):
        """更新课程专辑-权限测试"""

        res = self.admin_course.update_course_album(value, 0, '', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_delete_album_ok(self, createCourseTag_method):
        """删除课程专辑-正向用例"""
        # 创建课程专辑
        tagIds = [createCourseTag_method]
        album_name = 'dibo_test' + self.now
        res = self.admin_course.course_album_create(self.authorization, album_name, tagIds)
        album_id = res['data']['id']

        # 删除课程专辑
        res = self.admin_course.delete_course_album(self.authorization, album_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == "删除成功", f"接口返回data数据异常：{res['data']}"

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
    def test_admin_course_permission_delete_album(self, desc, value):
        """删除课程专辑-权限测试"""

        res = self.admin_course.delete_course_album(value, 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_album_ok(self, createCourseTag_method):
        """课程专辑-增删改查测试"""

        # 创建课程专辑
        tagIds = [createCourseTag_method]
        album_name = 'dibo_test' + self.now
        create_res = self.admin_course.course_album_create(self.authorization, album_name, tagIds)
        album_id = create_res['data']['id']

        # 分页查询课程专辑列表，验证创建课程专辑成功
        album_res1 = self.admin_course.course_album_list(self.authorization)['data']['content']
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
        update_res = self.admin_course.update_course_album(self.authorization, album_id, album_new_name, status=0)
        assert update_res['data']['id'] == album_id, f"接口返回data数据异常：{update_res['data']}"

        # 更新课程专辑后分页查询课程专辑列表，验证更新课程专辑成功
        album_res2 = self.admin_course.course_album_list(self.authorization, status=0)['data']['content']
        for album in album_res2:
            if album['id'] == album_id:
                assert album['name'] == album_new_name
                assert album['multilingualKey'] == 'en'
                assert album['status'] == 0
                break
        else:
            assert False, "更新课程专辑失败！"

        # 删除课程专辑
        delete_res = self.admin_course.delete_course_album(self.authorization, album_id)
        assert delete_res['data'] == "删除成功", f"接口返回data数据异常：{delete_res['data']}"

        # 删除课程专辑后分页查询状态为生效的课程专辑列表，验证删除课程专辑成功
        album_res3_0 = self.admin_course.course_album_list(self.authorization)['data']['content']
        album_ids = DataFrame(album_res3_0, columns=['id', 'name', 'tagIds'])['id'].tolist()
        assert album_id not in album_ids, "删除课程专辑失败"

        # 删除课程专辑后分页状态为废弃的查询课程专辑列表，验证删除课程专辑成功
        album_res3_1 = self.admin_course.course_album_list(self.authorization, status=0)['data']['content']
        album_ids = DataFrame(album_res3_1, columns=['id', 'name', 'tagIds'])['id'].tolist()
        assert album_id not in album_ids, "删除课程专辑失败"

    @pytest.mark.smoke
    def test_admin_course_positive_getByCourseIds_ok(self):
        """根据课程ID查询课程等级技能列表-正向用例"""
        courseIds = self.admin_course.course_listAll(self.admin_auth, 641364208128069)['data'][0]['id']
        res = self.admin_course.getByCourseIds(self.authorization, courseIds)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'][0]['courseId'] == courseIds, f"接口返回data数据异常：{res['data']}"
        skills_res = res['data'][0]['skills']
        for skill in skills_res:
            assert skill['educationType'] == 'Listening and Speaking Skills'
            assert skill['learningLevel'] == 'L1'
            assert skill['prerequisiteSkill'] == None

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
    def test_admin_course_permission_getByCourseIds(self, desc, value):
        """根据课程ID查询课程等级技能列表-权限测试"""

        res = self.admin_course.getByCourseIds(value, '', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_course_skills_ok(self):
        """分页查询课程等级技能列表-正向用例"""
        res = self.admin_course.course_skill_list(self.authorization)
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
    def test_admin_course_permission_course_skills(self, desc, value):
        """分页查询课程等级技能列表-权限测试"""

        res = self.admin_course.course_skill_list(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_course_positive_course_details_ok(self):
        """获取课程详情包括版本信息-正向用例"""
        topcategory_res = self.admin_course.getAlltopcategory(self.admin_auth)
        parentId = topcategory_res['data'][0]['id']
        category_res = self.admin_course.getAllsubcategory(self.admin_auth, parentId)
        for subcategory in category_res['data']:
            flag = False
            if subcategory['level'] == "1":
                categoryId = subcategory['id']
                courselistAll = self.admin_course.course_listAll(self.admin_auth, categoryId)
                for course in courselistAll['data']:
                    courseId = course['id']
                    course_details_res = self.admin_course.course_details(self.admin_auth, courseId)['data']['course']
                    if "Blending CVC words-L6" in course_details_res['skillList']:
                        print(course['name'])
                        flag= True
                        break
            if flag:
                break
        else:
            assert False

    @pytest.mark.release
    def test_admin_course_positive_addCourseStrategy_ok(self):
        """策略定义 - 增删改查检查 - 正向用例"""
        # 新增策略定义
        strategyId = "dibo_test_v1" + self.now
        pl = {
            "strategyId": strategyId
        }
        add_res = self.admin_course.addCourseStrategy(self.admin_auth, **pl)
        assert add_res['message'] == 'success', "新增策略定义失败！"
        # 查询策略定义列表，验证新增策略定义成功
        strategy_res1 = self.admin_course.courseStrategies(self.admin_auth)
        for strategy in strategy_res1['data']['content']:
            if strategy['strategyId'] == strategyId:
                strategy_id = strategy['id']
                assert strategy['enabled'] == True
                assert strategy['resetOnSegmentChange'] == False
                assert strategy['pattern'] == "A-B-C"
                assert strategy['patternBehavior'] == "LOOP_PATTERN"
                assert strategy['description'] == "默认课程分发策略"
                break
        else:
            assert False, '新增课程策略后，未在策略定义列表中查询到！'
        # 更新策略定义
        pl1 = {
            "strategyId": strategyId,
            "enabled": False,
            "resetOnSegmentChange": True,
            "pattern": "A-B-C-D",
            "patternBehavior": "LOOP_PATTERN",
            "description": "默认课程分发策略-"
        }
        update_res = self.admin_course.updateCourseStrategy(self.admin_auth, strategy_id, **pl1)
        assert update_res['message'] == 'success', "更新策略定义失败！"
        # 查询策略定义列表，验证更新策略定义成功
        strategy_res2 = self.admin_course.courseStrategies(self.admin_auth)
        for strategy in strategy_res2['data']['content']:
            if strategy['id'] == strategy_id:
                assert strategy['strategyId'] == strategyId
                assert strategy['enabled'] == pl1.get('enabled', False)
                assert strategy['resetOnSegmentChange'] == pl1.get('resetOnSegmentChange', False)
                assert strategy['pattern'] == pl1.get('pattern', False)
                assert strategy['patternBehavior'] == pl1.get('patternBehavior', False)
                assert strategy['description'] == pl1.get('description', False)
                break
        else:
            assert False, '更新课程策略后，未在策略定义列表中查询到！'

        delete_res = self.admin_course.deleteCourseStrategy(self.admin_auth, strategy_id)
        assert delete_res['message'] == 'success', "删除策略定义失败！"
        # 查询策略定义列表，验证删除策略定义成功
        strategy_res3 = self.admin_course.courseStrategies(self.admin_auth)
        strategy_ids = DataFrame(strategy_res3['data']['content'])['id'].tolist()
        assert strategy_id not in strategy_ids, '删除课程策略后，仍在策略定义列表中查询到！'

    @pytest.mark.release
    def test_admin_course_permission_addCourseStrategy(self):
        """新增策略定义-权限测试"""
        res = self.admin_course.addCourseStrategy('', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_permission_deleteCourseStrategy(self):
        """删除策略定义-权限测试"""
        res = self.admin_course.deleteCourseStrategy('', 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_permission_updateCourseStrategy(self):
        """更新策略定义-权限测试"""
        res = self.admin_course.updateCourseStrategy('', 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_permission_courseStrategies(self):
        """查询策略定义列表-权限测试"""
        res = self.admin_course.courseStrategies('', 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
            
    @pytest.fixture(scope='function')
    def createCourseStrategy(self):
        '''新增策略定义'''
        # 新增策略定义
        strategyId = "dibo_test_v1" + self.now
        pl = {
            "strategyId": strategyId
        }
        add_res = self.admin_course.addCourseStrategy(self.admin_auth, **pl)
        assert add_res['message'] == 'success', "新增策略定义失败！"
        assert add_res['message'] == 'success', "新增策略定义失败！"
        # 查询策略定义列表，验证新增策略定义成功
        strategy_res1 = self.admin_course.courseStrategies(self.admin_auth)
        for strategy in strategy_res1['data']['content']:
            if strategy['strategyId'] == strategyId:
                strategy_id = strategy['id']
                break
        else:
            assert False, '新增课程策略后，未在策略定义列表中查询到！'
        
        yield strategyId

        delete_res = self.admin_course.deleteCourseStrategy(self.admin_auth, strategy_id)
        assert delete_res['message'] == 'success', "删除策略定义失败！"

    @pytest.fixture(scope='function')
    def get_courseIds(self):
        """获取课程详情包括版本信息"""
        # 获取顶层课程目录列表
        topcategory_res = self.admin_course.getAlltopcategory(self.admin_auth)
        for category in topcategory_res['data']:
            parentId = category['id']
            # 获取课程子目录列表
            category_res1 = self.admin_course.getAllsubcategory(self.admin_auth, parentId)
            for subcategory in category_res1['data']:
                parentId1 = subcategory['id']
                category_res2 = self.admin_course.getAllsubcategory(self.admin_auth, parentId1)
                for subcategory2 in category_res2['data']:
                    categoryId = subcategory2['id']
                    # 获取分类下所有课程
                    courselistAll = self.admin_course.course_listAll(self.admin_auth, categoryId)['data']
                    if not courselistAll:
                        continue
                    courseIds = ','.join(DataFrame(courselistAll)[:3]['id'].tolist())
                    return courseIds

    @pytest.mark.release
    def test_admin_course_positive_addStrategyRule_ok(self, createCourseStrategy, get_courseIds):
        """新增课程规则 - 增删改查验证 - 正向用例"""
        # 新增策略定义
        strategyId = createCourseStrategy
        # 获取课程详情包括版本信息
        courseIds = get_courseIds
        # 新增课程规则
        add_res = self.admin_course.addStrategyRule(self.admin_auth, strategyId, courseIds)
        # 如果选中的课程已经添加课程规则则先移除
        if add_res['code'] == 100006:
            set_course = add_res['data']
            set_course = re.search(r"(\d+)", set_course).group(1).split(',')
            for course_id in set_course:
                # 查询课程规则列表，移除目标课程已参与的课程规则
                strategyRules0 = self.admin_course.strategyRules(self.admin_auth)
                for strategyRule in strategyRules0['data']['content']:
                    courseIds1 = strategyRule['courseIds'].split(',')
                    if course_id in courseIds1:
                        rule_id = strategyRule['id']
                        strategyId1 = strategyRule['strategyId']
                        new_courseIds = str(random.randint(1000, 9999))
                        update_res = self.admin_course.updateStrategyRule(self.admin_auth, rule_id, strategyId1, new_courseIds)
                        assert update_res['message'] == 'success'
                        break
            # 再次新增课程规则
            add_res1 = self.admin_course.addStrategyRule(self.admin_auth, strategyId, courseIds)
            assert add_res1['message'] == 'success'
        else:
            assert add_res['message'] == 'success', "新增课程规则失败！"
        # 查询课程规则列表，验证新增课程规则成功
        strategyRules1 = self.admin_course.strategyRules(self.admin_auth)
        for strategyRule in strategyRules1['data']['content']:
            if strategyRule['strategyId'] == strategyId:
                rule_id1 = strategyRule['id']
                assert strategyRule['courseCount'] == 3
                assert strategyRule['enabled'] == True
                assert strategyRule['courseIds'] == courseIds
                break
        else:
            assert False, '查询课程规则列表，新增课程规则不在列表中！'
        # 更新课程规则
        new_courseIds1 = ','.join(courseIds.split(',')[:2])
        update_res = self.admin_course.updateStrategyRule(self.admin_auth, rule_id1, strategyId, new_courseIds1,
                                                          enabled=False)
        assert update_res['message'] == 'success', "更新课程规则失败"
        # 查询课程规则列表，验证更新课程规则成功
        strategyRules2 = self.admin_course.strategyRules(self.admin_auth)
        for strategyRule in strategyRules2['data']['content']:
            if strategyRule['strategyId'] == strategyId:
                assert strategyRule['id'] == rule_id1
                assert strategyRule['courseCount'] == 2
                assert strategyRule['enabled'] == False
                assert strategyRule['courseIds'] == new_courseIds1
                break
        else:
            assert False, '查询课程规则列表，更新课程规则校验失败'
        # 删除课程规则
        delete_res = self.admin_course.deleteStrategyRule(self.admin_auth, rule_id1)
        assert delete_res['message'] == 'success', "删除课程规则失败！"
        # 查询课程规则列表，验证删除课程规则成功
        strategyRules3 = self.admin_course.strategyRules(self.admin_auth)
        rule_ids = DataFrame(strategyRules3['data']['content'])['id'].tolist()
        assert rule_id1 not in rule_ids, "删除课程规则失败！"

    @pytest.mark.release
    def test_admin_course_permission_addStrategyRule(self):
        """新增课程规则-权限测试"""
        res = self.admin_course.addStrategyRule('', 0,0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_permission_deleteStrategyRule(self):
        """删除课程规则-权限测试"""
        res = self.admin_course.deleteStrategyRule('', 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_permission_strategyRules(self):
        """查询课程规则列表-权限测试"""
        res = self.admin_course.strategyRules('', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_permission_updateStrategyRule(self):
        """更新课程规则-权限测试"""
        res = self.admin_course.updateStrategyRule('', 0, 0, '', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_positive_strategylevelRule_ok(self, createCourseStrategy, get_courseIds):
        """新增等级策略 - 增删改查验证 - 正向用例"""
        # 新增策略定义
        strategyId = createCourseStrategy
        # 新增等级策略
        levels = 'L11,L12'
        add_res = self.admin_course.addStrategylevelRule(self.admin_auth, strategyId, levels)
        # 如果等级已经被配置，则先删除配置该等级的等级策略
        if add_res['code'] == 100006:
            text = add_res['data']
            strategyId1 = re.search(r"([a-zA-Z0-9_]+(?:\d{14}))", text).group(0)
            # 查询等级策略列表，验证新增等级策略成功
            strategylevelRules1 = self.admin_course.strategylevelRules(self.admin_auth)
            for strategyRule in strategylevelRules1['data']['content']:
                if strategyRule['strategyId'] == strategyId1:
                    level_rule_id1 = strategyRule['id']
            # 删除等级策略
            delete_res = self.admin_course.deleteStrategylevelRule(self.admin_auth, level_rule_id1)
            assert delete_res['message'] == 'success', "删除等级策略失败！"
        else:
            assert add_res['message'] == 'success', "新增等级策略失败！"
        # 查询等级策略列表，验证新增等级策略成功
        strategylevelRules1 = self.admin_course.strategylevelRules(self.admin_auth)
        for strategyRule in strategylevelRules1['data']['content']:
            if strategyRule['strategyId'] == strategyId:
                level_rule_id = strategyRule['id']
                assert strategyRule['level'] == levels
                break
        else:
            assert False, '查询等级策略列表，新增等级策略不在列表中！'
        # 更新等级策略
        new_levels = 'L14,L15'
        update_res = self.admin_course.updateStrategylevelRule(self.admin_auth, level_rule_id, strategyId, new_levels)
        assert update_res['message'] == 'success', "更新等级策略失败"
        # 查询等级策略列表，验证更新等级策略成功
        strategylevelRules2 = self.admin_course.strategylevelRules(self.admin_auth)
        for strategyRule in strategylevelRules2['data']['content']:
            if strategyRule['strategyId'] == strategyId:
                assert strategyRule['id'] == level_rule_id
                assert strategyRule['level'] == new_levels
                break
        else:
            assert False, '查询等级策略列表，更新等级策略校验失败'
        # 删除等级策略
        delete_res = self.admin_course.deleteStrategylevelRule(self.admin_auth, level_rule_id)
        assert delete_res['message'] == 'success', "删除等级策略失败！"
        # 查询等级策略列表，验证删除等级策略成功
        strategylevelRules3 = self.admin_course.strategylevelRules(self.admin_auth)
        level_rule_ids = DataFrame(strategylevelRules3['data']['content'])['id'].tolist()
        assert level_rule_id not in level_rule_ids, "删除等级策略失败！"

    @pytest.mark.release
    def test_admin_course_permission_deleteStrategylevelRule(self):
        """删除等级策略-权限测试"""
        res = self.admin_course.deleteStrategylevelRule('', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_permission_strategylevelRules(self):
        """查询等级策略列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_course.strategylevelRules('', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_strategy_preview_ok(self):
        """预览当前草稿配置-正向用例"""
        res = self.admin_course.strategy_preview(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_permission_strategy_preview(self):
        """预览当前草稿配置-权限测试"""
        res = self.admin_course.strategy_preview('', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_publish_strategy_ok(self):
        """发布配置-正向用例"""
        res = self.admin_course.publish_strategy(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_permission_publish_strategy(self):
        """发布配置-权限测试"""
        res = self.admin_course.publish_strategy('', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_admin_course_strategy_history_detail_ok(self):
        """查询发布历史详情-正向用例"""
        res = self.admin_course.strategy_history_detail(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_admin_course_permission_strategy_history_detail(self):
        """查询发布历史详情-权限测试"""
        res = self.admin_course.strategy_history_detail('', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_admin_course_strategy_historys_ok(self):
        """查询发布历史列表-正向用例"""
        res = self.admin_course.strategy_historys(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_admin_course_permission_strategy_historys(self):
        """查询发布历史列表-权限测试"""
        res = self.admin_course.strategy_historys('', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_course_addVoiceMultilingual_ok(self, get_courseIds):
        """新增语音文案-正向用例-courseId + key + targetLanguage 组合不与现有重复"""
        # 获取课程详情包括版本信息
        course_id = get_courseIds.split(',')[0]
        # 新增语音文案
        key = 'dibo_test' + self.now
        pl = {
            "key": key,           # String，必填：环节标识（比如某一页、某一步骤的key）
            "targetLanguage": "en"    # String，必填：目标语言代码（如 "en"、"ar"）
        }
        add_res = self.admin_course.addVoiceMultilingual(self.authorization, course_id, **pl)
        assert add_res['message'] == 'success', "新增语音文案失败！"
        # 分页查询语音文案列表，新增语音文案成功
        search_res1 = self.admin_course.voiceMultilinguals(self.authorization, course_id, key=key, size=100)
        for item in search_res1['data']['content']:
            if item['key'] == key:
                voice_id = item['id']
                assert item['courseId'] == int(course_id)
                assert item['englishText'] == 'Hello'
                assert item['targetLanguage'] == "en"
                assert item['translatedText'] == 'Hello'
                assert item['audioStatus'] == 0
                audioUrl = item['audioUrl']
                break
        else:
            assert False, "新增语音文案失败，列表未查询到！"
        # 更新语音文案
        translatedTextNew = 'Happy Day'
        update_res = self.admin_course.updateVoiceMultilingual(self.authorization, voice_id, translatedTextNew)
        assert update_res['message'] == 'success', "更新语音文案失败！"
        # 分页查询语音文案列表，验证更新语音文案成功
        search_res2 = self.admin_course.voiceMultilinguals(self.authorization, course_id, key=key, size=100)
        for item in search_res2['data']['content']:
            if item['id'] == voice_id:
                assert item['courseId'] == int(course_id)
                assert item['englishText'] == 'Hello'
                assert item['targetLanguage'] == "en"
                assert item['translatedText'] == translatedTextNew
                assert item['audioStatus'] == 0
                audioUrlNew = item['audioUrl']
                break
        else:
            assert False
        # 删除语音文案
        delete_res = self.admin_course.deleteVoiceMultilingual(self.authorization, voice_id)
        assert delete_res['message'] == 'success', "删除语音文案失败！"
        # 分页查询语音文案列表，验证删除语音文案成功
        search_res3 = self.admin_course.voiceMultilinguals(self.authorization, course_id, key=key, size=100)
        if search_res3['data']['content']:
            voice_ids = DataFrame(search_res3['data']['content'])['id'].tolist()
            assert voice_id in voice_ids, "删除语音文案失败，列表还能查询到！"