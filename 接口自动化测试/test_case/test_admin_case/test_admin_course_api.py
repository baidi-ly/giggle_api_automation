import datetime
import sys
import os

import pandas as pd

from test_case.page_api.admin.admin_course_api import AdminCourseApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminCourse
class TestAdminCourse:

    def setup_class(self):
        self.admin = AdminCourseApi()
        self.authorization = self.admin.get_authorization()
        self.admin_authorization = self.admin.get_admin_authorization()

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
            ('expired_token', 'expired_token'),
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
            ('expired_token', 'expired_token'),
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
            ('expired_token', 'expired_token'),
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