from time import strftime

import pytest
from pandas import DataFrame

from test_case.page_api.admin.admin_quiz_api import AdminQuizApi
from test_case.page_api.school.school_api import SchoolApi
from config import RunConfig
from test_case.page_api.study_plan.study_plan_api import Study_planApi

base_url = RunConfig.baseurl

class TestStudyPlanApi:
    """
    学习计划 接口测试用例
    """

    def setup_class(self):
        self.study_plan = Study_planApi()
        self.authorization = self.study_plan.get_authorization()
        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.release
    def test_study_plan_positive_getList_ok(self):
        """学习计划包列表-正向用例"""
        res = self.study_plan.study_plan_list(self.authorization)
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
    def test_study_plan_permission_getList(self, desc, value):
        """学习计划包列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.study_plan.study_plan_list(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_study_plan_positive_studyPlan_details_ok(self):
        """学习计划包详情-正向用例"""
        res = self.study_plan.studyPlan_details(self.authorization)
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
    def test_study_plan_permission_studyPlan_details(self, desc, value):
        """学习计划包详情-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.study_plan.studyPlan_details(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 200, 500),
            ('float', 12.34, 200, 500),
            ('boolean', True, 200, 500),
            ('negative', -123, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
        ]
    )
    def test_study_plan_format_studyPlan_details_studyPlanId(self, desc, value, code, code_res):
        """学习计划包详情-数据格式测试(studyPlanId)"""
        try:
            res = self.study_plan.studyPlan_details(self.authorization, studyPlanId=value, code=code)
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

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 200),
            ('zero', 0, 200),
            ('max', 2147483647, 200),
        ]
    )
    def test_study_plan_boundary_studyPlan_details_studyPlanId(self, desc, value, code):
        """学习计划包详情-边界值测试(studyPlanId)"""
        res = self.study_plan.studyPlan_details(self.authorization, studyPlanId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_study_plan_scenario_studyPlan_details_invalid_studyPlanId(self):
        """学习计划包详情-场景异常-无效的studyPlanId"""
        studyPlanId = 999999999
        res = self.study_plan.studyPlan_details(self.authorization, studyPlanId=studyPlanId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_study_plan_positive_getUnits_ok(self):
        """学习计划单元列表-正向用例"""
        res = self.study_plan.study_plan_units(self.authorization)
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
    def test_study_plan_permission_getUnits(self, desc, value):
        """学习计划单元列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.study_plan.study_plan_units(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 200, 500),
            ('float', 12.34, 200, 500),
            ('boolean', True, 200, 500),
            ('negative', -123, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
        ]
    )
    def test_study_plan_format_getUnits_kidId(self, desc, value, code, code_res):
        """学习计划单元列表-数据格式测试(kidId)"""
        try:
            res = self.study_plan.study_plan_units(self.authorization, kidId=value, code=code)
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

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 200),
            ('zero', 0, 200),
            ('max', 2147483647, 200),
        ]
    )
    def test_study_plan_boundary_getUnits_kidId(self, desc, value, code):
        """学习计划单元列表-边界值测试(kidId)"""
        res = self.study_plan.study_plan_units(self.authorization, kidId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_study_plan_scenario_getUnits_invalid_kidId(self):
        """学习计划单元列表-场景异常-无效的kidId"""
        kidId = 999999999
        res = self.study_plan.study_plan_units(self.authorization, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_study_plan_positive_getContents_ok(self):
        """学习计划单元内容列表-正向用例"""
        res = self.study_plan.study_plan_contents(self.authorization)
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
    def test_study_plan_permission_getContents(self, desc, value):
        """学习计划单元内容列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.study_plan.study_plan_contents(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 200, 500),
            ('float', 12.34, 200, 500),
            ('boolean', True, 200, 500),
            ('negative', -123, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
        ]
    )
    def test_study_plan_format_getContents_unitId(self, desc, value, code, code_res):
        """学习计划单元内容列表-数据格式测试(unitId)"""
        try:
            res = self.study_plan.study_plan_contents(self.authorization, unitId=value, code=code)
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

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 200, 500),
            ('float', 12.34, 200, 500),
            ('boolean', True, 200, 500),
            ('negative', -123, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
        ]
    )
    def test_study_plan_format_getContents_kidId(self, desc, value, code, code_res):
        """学习计划单元内容列表-数据格式测试(kidId)"""
        try:
            res = self.study_plan.study_plan_contents(self.authorization, kidId=value, code=code)
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

    @pytest.mark.release
    def test_study_plan_scenario_getContents_invalid_kidId(self):
        """学习计划单元内容列表-场景异常-无效的kidId"""
        kidId = 999999999
        res = self.study_plan.study_plan_contents(self.authorization, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_study_plan_positive_getProgress_ok(self):
        """获取学习计划进度-正向用例"""
        res = self.study_plan.study_plan_progress(self.authorization)
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
    def test_study_plan_permission_getProgress(self, desc, value):
        """获取学习计划进度-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.study_plan.study_plan_progress(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 200, 500),
            ('float', 12.34, 200, 500),
            ('boolean', True, 200, 500),
            ('negative', -123, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
        ]
    )
    def test_study_plan_format_getProgress_studyPlanId(self, desc, value, code, code_res):
        """获取学习计划进度-数据格式测试(studyPlanId)"""
        try:
            res = self.study_plan.study_plan_progress(self.authorization, studyPlanId=value, code=code)
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
    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 200, 500),
            ('float', 12.34, 200, 500),
            ('boolean', True, 200, 500),
            ('negative', -123, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
        ]
    )
    def test_study_plan_format_getProgress_kidId(self, desc, value, code, code_res):
        """获取学习计划进度-数据格式测试(kidId)"""
        try:
            res = self.study_plan.study_plan_progress(self.authorization, kidId=value, code=code)
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

    @pytest.mark.release
    def test_study_plan_scenario_getProgress_invalid_kidId(self):
        """获取学习计划进度-场景异常-无效的kidId"""
        kidId = 999999999
        res = self.study_plan.study_plan_progress(self.authorization, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_study_plan_positive_complete_ok(self):
        """完成学习计划内容-正向用例"""
        res = self.study_plan.studyplan_content_complete(self.authorization)
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
    def test_study_plan_permission_complete(self, desc, value):
        """完成学习计划内容-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.study_plan.studyplan_content_complete(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"