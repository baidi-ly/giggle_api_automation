import datetime
import sys
import os

from config import RunConfig
from test_case.page_api.book.book_api import BookApi
from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.user.user_api import UserApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

expired_token = RunConfig.expired_token

@pytest.mark.Kid
class TestKid:

    def setup_class(self):
        self.kid = KidApi()
        self.course = CourseApi()
        self.user = UserApi()
        self.authorization = self.kid.get_authorization()[0]

    @pytest.mark.smoke
    def test_kid_positive_check_placement_ok(self):
        """查询是否需要定级-正向用例"""
        kids_res = self.kid.getKids(self.authorization)
        for kid in kids_res['data']:
            if kid['name'] == 'New Kid':
                kid_id = kid['id']
        res = self.kid.check_placement(self.authorization, kid_id)
        assert not res['data']['needPlacement']

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

    @pytest.mark.smoke
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

    @pytest.mark.smoke
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
        res = self.kid.learningLevel(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_guest_sync_and_placement_positive(self):
        """访客模式数据同步或注册用户定级数据保存-正向用例"""

        # 1. 获取孩子列表，找到名为 'New Kid' 的孩子
        kids_res = self.kid.getKids(self.authorization)
        assert kids_res['code'] == 200, f"获取孩子列表失败: {kids_res}"

        kid_id = None
        for kid in kids_res['data']:
            if kid['name'] == 'New Kid':
                kid_id = kid['id']
                break

        assert kid_id is not None, "未找到名为 'New Kid' 的孩子"
        print(f"找到孩子 ID: {kid_id}")

        # 2. 用户第三方登录后信息注册同步（访客转正式用户）
        username = 'di.bbb@giggleacademy.me'
        password = 'Bd2243422434~'
        sync_res = self.user.registerInfo_sync(self.authorization, username, password)
        assert sync_res['code'] == 200, f"用户注册同步失败: {sync_res}"
        print(f"用户注册同步成功: {sync_res}")

        # 3. 查询是否需要定级
        check_res = self.kid.check_placement(self.authorization, kid_id)
        assert check_res['code'] == 200, f"查询定级状态失败: {check_res}"
        print(f"定级检查结果: {check_res}")

        # 4. 访客模式数据同步或注册用户定级数据保存
        # 注意：这里可能需要传入 learningLevel 参数，如 'L1', 'L2' 等
        ll_res = self.kid.learningLevel(self.authorization, kid_id)
        assert ll_res['code'] == 200, f"保存定级数据失败: {ll_res}"
        print(f"定级数据保存结果: {ll_res}")

        # 5. 查询晋级进度条
        lp_res = self.kid.getLearningProgress(self.authorization)
        assert lp_res['code'] == 200, f"查询晋级进度失败: {lp_res}"
        print(f"晋级进度: {lp_res}")

        # 6. 验证定级结果（可选，再次调用确认）
        res = self.kid.learningLevel(self.authorization, kid_id)
        assert res['code'] == 200, f"验证定级结果失败: {res}"
        print(f"最终定级结果: {res}")

        return res ^ 8