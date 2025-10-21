import sys
import os

import pandas as pd

from test_case.page_api.admin.admin_booktranslation_api import AdminBooktranslationApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminBooktranslation
class TestAdminBooktranslation:

    def setup_class(self):
        self.admin_booktranslation = AdminBooktranslationApi()
        self.authorization = self.admin_booktranslation.get_admin_authorization()

    def test_admin_booktranslation_positive_update_concurrent_threshold_ok(self):
        """更新书籍翻译并发阈值设置-正向用例"""
        threshold = 5
        res = self.admin_booktranslation.concurrent_threshold(self.authorization, threshold)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == "设置成功", f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_booktranslation_permission_update_concurrent_threshold(self, desc, value):
        """更新书籍翻译并发阈值设置-权限测试"""
        res = self.admin_booktranslation.concurrent_threshold(value, 5, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 400),
            ('null', None, 500),
        ]
    )
    def test_admin_booktranslation_required_update_concurrent_threshold_threshold(self, desc, value, code):
        """更新书籍翻译并发阈值设置-必填字段测试(threshold)"""
        if desc == 'missing':
            threshold = 5
            pl = {'pop_items': 'threshold'}
        else:
            pl = {}
            threshold = value
        res = self.admin_booktranslation.concurrent_threshold(self.authorization, threshold, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【internal server error】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
        else:
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【'invalid parameter'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('shortest', 0, 200),
            ('longest', 999999999, 200),
        ]
    )
    def test_admin_booktranslation_boundary_update_concurrent_threshold_threshold(self, desc, value, code):
        """更新书籍翻译并发阈值设置-边界值测试(threshold)"""
        res = self.admin_booktranslation.concurrent_threshold(self.authorization, threshold=value, code=code)
        if desc == 'longest':
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
        else:
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【'invalid parameter'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"