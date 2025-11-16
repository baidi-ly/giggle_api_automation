import sys
import os

import pandas as pd

from test_case.page_api.admin.admin_tabstorybook_api import AdminTabstorybookApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminTabStoryBookApi
class TestAdminTabStoryBookApi:

    def setup_class(self):
        self.admin_tab = AdminTabstorybookApi()
        self.authorization = self.admin_tab.get_admin_authorization()[0]

    def test_admin_tabstorybook_positive_visible_ok(self):
        """设置故事书Tab显示状态-正向用例"""
        visible = True
        res = self.admin_tab.visible(self.authorization, visible)
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
    def test_admin_tabstorybook_permission_visible(self, desc, value):
        """设置故事书Tab显示状态-权限测试"""
        res = self.admin_tab.visible(value, True, code=401)
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
    def test_admin_tabstorybook_required_visible_visible(self, desc, value, code):
        """设置故事书Tab显示状态-必填字段测试(visible)"""
        if desc == 'missing':
            visible = True
            pl = {'pop_items': 'visible'}
        else:
            pl = {}
            visible = value
        res = self.admin_tab.visible(self.authorization, visible, code=code, **pl)
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【internal server error】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
        else:
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【100006】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【'invalid parameter'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('true', True, 200),
            ('false', False, 200),
        ]
    )
    def test_admin_tabstorybook_boundary_visible_visible(self, desc, value, code):
        """设置故事书Tab显示状态-边界值测试(visible)"""
        res = self.admin_tab.visible(self.authorization, visible=value, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == "设置成功", f"接口返回data数据异常：{res['data']}"