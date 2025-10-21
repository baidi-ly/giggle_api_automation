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
        res = self.admin_instructional.create(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_instructionaldomain_positive_create_twice(self):
        """创建教学维度标签-正向用例"""
        self.admin_instructional.create(self.authorization)
        res = self.admin_instructional.create(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100055, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'Resource name already exists', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == 'Resource name already exists', f"接口返回data数据异常：{res['data']}"

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
        res = self.admin_instructional.create(value, code=401)
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
            ('empty', "", 400),
            ('null', None, 500),
        ]
    )
    def test_admin_instructionaldomain_required_create_name(self, desc, value, code):
        """创建教学维度标签-必填字段测试(req)"""
        if desc == 'missing':
            pl = {'pop_items': 'name'}
        else:
            pl = {'name': value}
        res = self.admin_instructional.create(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        else:
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【100006】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min_length', "", 400),
            ('max_length', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 400),
        ]
    )
    def test_admin_instructionaldomain_boundary_create_name(self, desc, value, code):
        """创建教学维度标签-边界值测试(req)"""
        res = self.admin_instructional.create(self.authorization, name=value, code=code)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_instructionaldomain_positive_getList_ok(self):
        """获取所有教学维度标签-正向用例"""
        res = self.admin_instructionaldomain.getList(self.authorization)
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
    def test_admin_instructionaldomain_permission_getList(self, desc, value):
        """获取所有教学维度标签-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_instructionaldomain.getList(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

