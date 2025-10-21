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

    def test_admin_booktranslation_positive_concurrent_threshold_ok(self):
        """获取书籍翻译并发阈值设置-正向用例"""
        res = self.admin_booktranslation.concurrent_threshold(self.authorization)
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
    def test_admin_booktranslation_permission_concurrent_threshold(self, desc, value):
        """获取书籍翻译并发阈值设置-权限测试"""
        res = self.admin_booktranslation.concurrent_threshold(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_admin_booktranslation_positive_update_concurrent_threshold_ok(self):
        """更新书籍翻译并发阈值设置-正向用例"""
        threshold = 5
        res = self.admin_booktranslation.update_concurrent_threshold(self.authorization, threshold)
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
    def test_admin_booktranslation_permission_update_concurrent_threshold(self, desc, value):
        """更新书籍翻译并发阈值设置-权限测试"""
        res = self.admin_booktranslation.update_concurrent_threshold(value, 5)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', ""),
            ('null', None),
        ]
    )
    def test_admin_booktranslation_required_update_concurrent_threshold_threshold(self, desc, value):
        """更新书籍翻译并发阈值设置-必填字段测试(threshold)"""
        if desc == 'missing':
            pl = {'pop_items': 'threshold'}
        else:
            pl = {'threshold': value}
        res = self.admin_booktranslation.update_concurrent_threshold(authorization=self.authorization, threshold=5, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('integer', 123),
            ('float', 12.3),
            ('boolean', True),
            ('array', [1, 2, 3]),
            ('object', {'key': 'value'}),
            ('special_chars', '!@#$%^&*()_+-=[]{}|;\':",./<>?'),
            ('email_format', 'test@example.com'),
            ('phone_format', '13800138000'),
            ('date_format', '2023-12-25'),
            ('emoji', '😀🎉🚀'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '中文测试'),
            ('json_string', '{"key": "value"}'),
            ('xml_string', '<root><item>test</item></root>'),
            ('url_string', 'https://www.example.com'),
            ('base64_string', 'SGVsbG8gV29ybGQ='),
            ('html_entities', "&lt;script&gt;alert('test')&lt;/script&gt;"),
            ('url_encoding', '%3Cscript%3Ealert%28%27test%27%29%3C%2Fscript%3E'),
            ('base64_encoding', 'PHNjcmlwdD5hbGVydCgndGVzdCcpPC9zY3JpcHQ+'),
            ('hex_encoding', '\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e'),
            ('double_encoding', '%253Cscript%253E'),
            ('format_string', '%x%x%x%x%x%x%x%x%x%x'),
        ]
    )
    def test_admin_booktranslation_format_update_concurrent_threshold_threshold(self, desc, value):
        """更新书籍翻译并发阈值设置-数据格式测试(threshold)"""
        res = self.admin_booktranslation.update_concurrent_threshold(self.authorization, threshold=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', 0),
            ('longest', 999999999),
        ]
    )
    def test_admin_booktranslation_boundary_update_concurrent_threshold_threshold(self, desc, value):
        """更新书籍翻译并发阈值设置-边界值测试(threshold)"""
        res = self.admin_booktranslation.update_concurrent_threshold(self.authorization, threshold=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_admin_booktranslation_scenario_update_concurrent_threshold_invalid_threshold(self):
        """更新书籍翻译并发阈值设置-场景异常-无效的threshold"""
        threshold = -1
        res = self.admin_booktranslation.update_concurrent_threshold(self.authorization, threshold=threshold)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"