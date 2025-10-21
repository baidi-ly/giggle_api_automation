import sys
import os

from test_case.page_api.admin.admin_instructionaldomain_api import AdminInstructionaldomainApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminInstructionalDomain
class TestAdminInstructionalDomain:

    def setup_class(self):
        self.admin_instructional = AdminInstructionaldomainApi()
        self.authorization = self.admin_instructional.get_admin_authorization()

    @pytest.mark.release
    def test_admin_instructionaldomain_positive_create_ok(self):
        """创建教学维度标签-正向用例"""
        res = self.admin_instructionaldomain.create(self.authorization)
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
    def test_admin_instructionaldomain_permission_create(self, desc, value):
        """创建教学维度标签-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_instructionaldomain.create(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_admin_instructionaldomain_required_create_name(self, desc, value, code):
        """创建教学维度标签-必填字段测试(req)"""
        if desc == 'missing':
            pl = {'pop_items': 'name'}
        else:
            pl = {'name': value}
        res = self.admin_instructionaldomain.create(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        else:
            assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
            assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
            assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('integer', 123, 200, 500),
            ('float', 12.3, 200, 500),
            ('boolean', True, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('email_format', 'test@example.com', 200, 500),
            ('phone_format', '13800138000', 200, 500),
            ('date_format', '2023-12-25', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 200, 500),
            ('unicode', 'chinese_test', 200, 500),
            ('json_string', '{"key": "value"}', 200, 500),
            ('xml_string', '<root><item>test</item></root>', 200, 500),
            ('url_string', 'https://www.example.com', 200, 500),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 500),
        ]
    )
    def test_admin_instructionaldomain_format_create_name(self, desc, value, code, code_res):
        """创建教学维度标签-数据格式测试(req)"""
        try:
            res = self.admin_instructionaldomain.create(self.authorization, name=value, code=code)
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
            ('min_length', "", 500),
            ('max_length', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 500),
        ]
    )
    def test_admin_instructionaldomain_boundary_create_name(self, desc, value, code):
        """创建教学维度标签-边界值测试(req)"""
        res = self.admin_instructionaldomain.create(self.authorization, name=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"