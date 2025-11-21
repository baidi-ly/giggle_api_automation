import datetime
import sys
import os

from config import RunConfig
from test_case.page_api.book.book_api import BookApi
from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.kid.kid_api import KidApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

expired_token = RunConfig.expired_token

@pytest.mark.Kid
class TestKid:

    def setup_class(self):
        self.kid = KidApi()
        self.course = CourseApi()
        self.authorization = self.kid.get_authorization()[0]

    @pytest.mark.release
    def test_kid_positive_check_placement_ok(self):
        """查询是否需要定级-正向用例"""
        kids_res = self.kid.getKids(self.authorization)
        for kid in kids_res['data']:
            if kid['name'] == 'New Kid':
                kid_id = kid['id']
        res = self.kid.check_placement(self.authorization, kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'  # TODO
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
    def test_kid_permission_check_placement(self, desc, value):
        """查询是否需要定级-权限测试"""
        kids_res = self.kid.getKids(self.authorization)
        for kid in kids_res['data']:
            if kid['name'] == 'New Kid':
                kid_id = kid['id']
        res = self.kid.check_placement(value, kid_id, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_kid_positive_getLearningProgress_ok(self):
        """查询晋级进度条-正向用例"""
        kids_res = self.kid.getKids(self.authorization)
        for kid in kids_res['data']:
            if kid['name'] == 'New Kid':
                kid_id = kid['id']
        res = self.kid.getLearningProgress(self.authorization, kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['kidId'] == kid_id, f"接口返回data数据异常：{res['data']}"

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
    def test_kid_permission_getLearningProgress(self, desc, value):
        """查询晋级进度条-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.kid.getLearningProgress(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_kid_positive_learningLevel_ok(self):
        """访客模式数据同步或注册用户定级数据保存-正向用例"""
        kids_res = self.kid.getKids(self.authorization)
        for kid in kids_res['data']:
            if kid['name'] == 'New Kid':
                kid_id = kid['id']
        res = self.kid.learningLevel(self.authorization, kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['success'] == True, f"接口返回data数据异常：{res['data']}"

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
    def test_kid_permission_learningLevel(self, desc, value):
        """访客模式数据同步或注册用户定级数据保存-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.kid.learningLevel(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
