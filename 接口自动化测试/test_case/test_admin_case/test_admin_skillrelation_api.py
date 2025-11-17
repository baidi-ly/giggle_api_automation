import datetime
import sys
import os
from time import strftime

from pandas import DataFrame

import config
from test_case.page_api.admin.admin_skillrelation_api import AdminSkillrelationApi
from test_case.page_api.kid.kid_api import KidApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.admin
@pytest.mark.adminSkillRelation
class TestAdminSkillRelation:

    def setup_class(self):
        self.admin = AdminSkillrelationApi()
        self.authorization = self.admin.get_admin_authorization()[0]

        self.kid = KidApi()
        self.kid_id = self.kid.getKids(self.authorization)["data"][0]['id']

        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.release
    def test_admin_skillrelation_positive_importSkillRelation_ById_ok(self):
        """根据ID导入技能关系-正向用例"""
        res = self.admin.importSkillRelation_ById(self.authorization)
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
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_skillrelation_permission_importSkillRelation_ById(self, desc, value):
        """根据ID导入技能关系-权限测试"""
        res = self.admin.importSkillRelation_ById(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_skillrelation_positive_importByName_ok(self):
        """根据名称导入技能关系-正向用例"""
        res = self.admin.importSkillRelation_ByName(self.authorization)
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
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_skillrelation_permission_importByName(self, desc, value):
        """根据名称导入技能关系-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin.importSkillRelation_ByName(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"