import datetime
import sys
import os
from time import strftime

import config
from test_case.page_api.admin.admin_kid_api import AdminKidApi
from test_case.page_api.kid.kid_api import KidApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.admin
@pytest.mark.adminKid
class TestAdminkid:

    def setup_class(self):
        self.admin_kid = AdminKidApi()
        self.authorization = self.admin_kid.get_admin_authorization()[0]

        self.kid = KidApi()
        self.kid_id = self.kid.getKids(self.authorization)["data"][0]['id']

        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.release
    def test_admin_kid_positive_getInteractionPreference_ok(self):
        """查询孩子互动偏好-正向用例"""
        res = self.admin_kid.getInteractionPreference(self.authorization, self.kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['kidId'] == str(self.kid_id), f"接口返回data数据异常：{res['data']}"
        assert 'preferences' in res['data']

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
    def test_admin_kid_permission_getInteractionPreference(self, desc, value):
        """查询孩子互动偏好-权限测试"""
        res = self.admin_kid.getInteractionPreference(value, 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_kid_positive_getSkillMastery_ok(self):
        """获取学生技能掌握程度-正向用例"""
        res = self.admin_kid.getSkillMastery(self.authorization, self.kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['kidId'] == str(self.kid_id), f"接口返回data数据异常：{res['data']}"
        assert 'skillMasteryMap' in res['data']

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
    def test_admin_kid_permission_getSkillMastery(self, desc, value):
        """获取学生技能掌握程度-权限测试"""
        res = self.admin_kid.getSkillMastery(value, 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_kid_positive_getKidTags_ok(self):
        """获取用户标签-正向用例"""
        res = self.admin_kid.getKidTags(self.authorization, self.kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['kidId'] == str(self.kid_id), f"接口返回data数据异常：{res['data']}"
        assert res['data']['childAge'] == 0

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
    def test_admin_kid_permission_getKidTags(self, desc, value):
        """获取用户标签-权限测试"""
        res = self.admin_kid.getKidTags(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_kid_positive_update_ok(self):
        """更新用户标签-正向用例"""
        res = self.admin_kid.updateKidTags(self.authorization, self.kid_id, learningLevel='L2')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == True, f"接口返回data数据异常：{res['data']}"

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
    def test_admin_kid_permission_updateKidTags(self, desc, value):
        """更新用户标签-权限测试"""
        res = self.admin_kid.updateKidTags(value, 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.fixture(scope="class")
    def getSecondekidId(self):
        '''类前置 - 获取kidId'''
        kid_res = self.kid.getKids(self.authorization)['data']
        for kid in kid_res:
            if kid['name'] == "dibo_test6":
                kid_id = kid['id']
                break
        yield kid_id

    @pytest.mark.release
    def test_admin_kid_positive_updateSkillMastery_ok(self, getSecondekidId):
        """更新用户技能标签-正向用例"""
        kid_id = getSecondekidId
        skillMasteryMap = self.admin_kid.getSkillMastery(self.authorization, kid_id)['data']['skillMasteryMap']
        for k, v in skillMasteryMap.items():
            if k == 'Letter Recognition-L1':
                pl = {
                    "kidId": kid_id,
                    "skill": v['skill'],
                    "masteryScore": 74.0,
                    "masteryState": "Practicing",
                    "componentExposureRate": 0.5
                }
        res = self.admin_kid.updateSkillMastery(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"