import datetime
import sys
import os

from test_case.page_api.admin.admin_donate_api import AdminDonateApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminDonate
class TestAdminDonate:

    def setup_class(self):
        self.admin_donate = AdminDonateApi()
        self.authorization = self.admin_donate.get_admin_authorization()

    @pytest.mark.smoke
    def test_donate_positive_getList_ok(self):
        """分页查询支出记录列表-正向用例"""
        res = self.admin_donate.getList(self.authorization)
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
    def test_donate_permission_getList(self, desc, value):
        """分页查询支出记录列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_donate.getList(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_donate_positive_updateRemark_ok(self):
        """更新支出记录的备注、详情URL和分类-正向用例"""
        transactionId = self.admin_donate.getList(self.authorization)['data']['content'][0]['id']
        res = self.admin_donate.updateRemark(self.authorization, id=transactionId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == "支出记录已更新", f"接口返回data数据异常：{res['data']}"
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_donate_permission_updateRemark(self, desc, value):
        """更新支出记录的备注、详情URL和分类-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_donate.updateRemark(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
    def test_donate_boundary_updateRemark_category(self):
        """更新支出记录的备注、详情URL和分类-边界值测试(category)"""
        category = "test2"
        transactionId = self.admin_donate.getList(self.authorization)['data']['content'][0]['id']
        res = self.admin_donate.updateRemark(self.authorization, category=category, id=transactionId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == "支出记录已更新", f"接口返回data数据异常：{res['data']}"
    def test_donate_boundary_updateRemark_detailUrl(self):
        """更新支出记录的备注、详情URL和分类-边界值测试(category)"""
        detailUrl = "https://chat18.aichatos.xyz/#/chat/1702608998643"
        transactionId = self.admin_donate.getList(self.authorization)['data']['content'][0]['id']
        res = self.admin_donate.updateRemark(self.authorization, category=detailUrl, id=transactionId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == "支出记录已更新", f"接口返回data数据异常：{res['data']}"
    def test_donate_boundary_updateRemark_remark(self):
        """更新支出记录的备注、详情URL和分类-边界值测试(category)"""
        detailUrl = "remark1"
        transactionId = self.admin_donate.getList(self.authorization)['data']['content'][0]['id']
        res = self.admin_donate.updateRemark(self.authorization, remark=detailUrl, id=transactionId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == "支出记录已更新", f"接口返回data数据异常：{res['data']}"

    def test_donate_scenario_updateRemark_invalid_transactionId(self):
        """更新支出记录的备注、详情URL和分类-边界值测试(transactionId)"""
        id = "0x66711962a74056d7e6bd4cab7be5c03ec35b76ace90cc38e120b1d0e2087e8d8"
        res = self.admin_donate.updateRemark(self.authorization, id=id, code=400)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100006, f"接口返回状态码异常: 预期【404】，实际【{res['code']}】"
        assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

