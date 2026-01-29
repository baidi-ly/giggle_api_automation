import time
from time import strftime

import pytest
import sys
import os

from config import RunConfig
from test_case.page_api.admin.admin_curriculum_api import AdminCurriculumApi
from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.curriculum.curriculum_api import CurriculumApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.learning.learning_api import LearningApi
from test_case.page_api.school.school_api import SchoolApi
from test_case.page_api.user.user_api import UserApi

sys.path.append(os.getcwd())
sys.path.append("..")

expired_token = RunConfig.expired_token

@pytest.mark.User
class TestUser:

    def setup_class(self):
        self.user = UserApi()
        self.kid = KidApi()
        self.learning = LearningApi()
        self.school = SchoolApi()
        self.curriculum = CurriculumApi()
        self.authorization, self.userId = self.user.get_authorization()
        self.course = CourseApi()

        self.now = strftime("%Y%m%d%H%M%S")

        try:
            # 获取孩子数据
            kids_res = self.kid.getKids(self.authorization)
            self.kid_name = 'New Kid'
            for kid in kids_res['data']:
                if kid['name'] == self.kid_name:
                    self.kid_id = kid['id']
                    break
        except Exception as e:
            print(f'获取孩子失败，原因是：{e}')

    @pytest.fixture(scope="class")
    def get_userIds(self):
        '''方法前置 - 创建kidId'''
        # 创建小孩账户
        couerseList = self.course.listAllWithLevel(self.authorization)["data"]
        yield couerseList

    @pytest.fixture(scope="class")
    def getkidId(self):
        '''类前置 - 获取kidId'''
        kidId = self.kid.getKids(self.authorization)
        yield kidId

    @pytest.mark.smoke
    def test_user_videoWhitelist_update_normal(self, get_userIds):
        """test_user_videoWhitelist_update_normal, test_user_api.py:63"""
        # 获取孩子
        userIds = get_userIds
        # 视频白名单用户全量更新
        event_res = self.user.update_videoWhitelist(self.authorization, userIds)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    def test_user_videoWhitelist_update_empty(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        userIds = []
        event_res = self.user.update_videoWhitelist(self.authorization, userIds)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    def test_user_videoWhitelist_update_wrong(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        userIds = [111, -9999, "~!@#", "", ()]
        event_res = self.user.update_videoWhitelist(self.authorization, userIds)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.smoke
    def test_user_bindWechat_normal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        code = "18380143661"
        event_res = self.user.bindWechat(self.authorization, code)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"

    def test_user_bindWechat_abnormal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        code = "18380143661"
        event_res = self.user.bindWechat(self.authorization, code)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'WeChat authorization code is invalid'
        assert event_res["data"] == 'WeChat authorization code is invalid'

    @pytest.mark.parametrize("code", [123, 123.4, True, "!@#~"], ids=["integer", "float", "boolen", "special characters"])
    def test_user_bindWechat_wrong(self, code):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.bindWechat(self.authorization, code)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'WeChat authorization code is invalid'
        assert event_res["data"] == 'WeChat authorization code is invalid'

    def test_user_bindWechat_null(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.bindWechat(self.authorization, '')
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'WeChat authorization code is invalid'

    def test_user_bindWechat_withoutCode(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        pl = {"pop_item": "code"}
        event_res = self.user.bindWechat(self.authorization, '', **pl)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'WeChat authorization code is invalid'

    def test_user_bindWechat_unauthorized(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        code = "18380143661"
        self.user.bindWechat('', code, status_code=401)

    def test_user_unbindWechat_abnormal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.unbindWechat(self.authorization)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    def test_user_unbindWechat_normal(self):
        """解绑微信账号"""
        # 解绑微信账号
        event_res = self.user.unbindWechat(self.authorization)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    def test_user_unbindWechat_unauthorized(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.unbindWechat('', code=403)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    def test_user_bindApple_normal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        identifyToken = "18380143661"
        event_res = self.user.bindApple(self.authorization, identifyToken)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.parametrize("identifyToken", [123, 123.4, True, "!@#~"], ids=["integer", "float", "boolen", "special characters"])
    def test_user_bindApple_wrong(self, identifyToken):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.bindApple(self.authorization, identifyToken=identifyToken)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    def test_user_bindApple_null(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.user.bindApple(self.authorization)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.smoke
    def test_noargs_auto_basic(self):
        """AI创建故事书消耗giggles"""
        res = self.user.aiStoryCreation(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.smoke
    def test_user_positive_getAzureconfig_ok(self):
        """获取 Azure 配置-正向用例"""
        res = self.user.getAzureconfig(authorization=self.authorization, **{})
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    def test_user_permission_getAzureconfig_no_auth(self):
        """获取 Azure 配置-未登录"""
        res = self.user.getAzureconfig()
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    def test_user_permission_getAzureconfig_expired_token(self):
        """获取 Azure 配置-鉴权异常-expired_token"""
        res = self.user.getAzureconfig(authorization='expired_token')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    def test_user_permission_getAzureconfig_invalid_token(self):
        """获取 Azure 配置-鉴权异常-invalid_token"""
        res = self.user.getAzureconfig(authorization='invalid_token')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.smoke
    def test_user_positive_sendemail_ok(self):
        """发送邮箱验证码接口-正向用例"""
        res = self.user.sendemail(self.authorization)
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
    def test_user_permission_sendemail(self, desc, value):
        """发送邮箱验证码接口-权限测试"""
        res = self.user.sendemail(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_user_required_sendemail_email(self, desc, value):
        """发送邮箱验证码接口-必填字段测试(email)"""
        if desc == 'missing':
            pl = {'pop_items': 'email'}
        else:
            pl = {'email': value}
        res = self.user.sendemail(authorization=self.authorization, **pl)
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
    def test_user_format_sendemail_email(self, desc, value):
        """发送邮箱验证码接口-数据格式测试(email)"""
        res = self.user.sendemail(self.authorization, email=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_user_boundary_sendemail_email(self, desc, value):
        """发送邮箱验证码接口-边界值测试(email)"""
        res = self.user.sendemail(self.authorization, email=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_user_scenario_sendemail_invalid_email(self):
        """发送邮箱验证码接口-场景异常-无效的email"""
        email = 'INVALID_VALUE'
        res = self.user.sendemail(self.authorization, email=email)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('sql_injection', "' OR '1'='1"),
            ('xss_script', "<script>alert('XSS')</script>"),
            ('xss_img', "<img src=x onerror=alert('XSS')>"),
            ('xss_iframe', "<iframe src=javascript:alert('XSS')></iframe>"),
            ('xml_injection', "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"),
            ('unicode_attack', '\\x00\\x01\\x02'),
            ('crlf_injection', 'test%0d%0aSet-Cookie: admin=true'),
            ('http_header_injection', 'test%0d%0aX-Injected: true'),
            ('log_injection', 'test%0d%0a[ERROR] Injected log entry'),
            ('code_injection', "eval('alert(1)')"),
            ('regex_dos', '((a+)+)+$'),
        ]
    )
    def test_user_security_sendemail_email(self, desc, value):
        """发送邮箱验证码接口-安全测试(email)"""
        res = self.user.sendemail(self.authorization, email=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_user_required_sendemail_scene(self, desc, value):
        """发送邮箱验证码接口-必填字段测试(scene)"""
        if desc == 'missing':
            pl = {'pop_items': 'scene'}
        else:
            pl = {'scene': value}
        res = self.user.sendemail(authorization=self.authorization, **pl)
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
    def test_user_format_sendemail_scene(self, desc, value):
        """发送邮箱验证码接口-数据格式测试(scene)"""
        res = self.user.sendemail(self.authorization, scene=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_user_boundary_sendemail_scene(self, desc, value):
        """发送邮箱验证码接口-边界值测试(scene)"""
        res = self.user.sendemail(self.authorization, scene=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_user_scenario_sendemail_invalid_scene(self):
        """发送邮箱验证码接口-场景异常-无效的scene"""
        scene = 'INVALID_VALUE'
        res = self.user.sendemail(self.authorization, scene=scene)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('sql_injection', "' OR '1'='1"),
            ('xss_script', "<script>alert('XSS')</script>"),
            ('xss_img', "<img src=x onerror=alert('XSS')>"),
            ('xss_iframe', "<iframe src=javascript:alert('XSS')></iframe>"),
            ('xml_injection', "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"),
            ('unicode_attack', '\\x00\\x01\\x02'),
            ('crlf_injection', 'test%0d%0aSet-Cookie: admin=true'),
            ('http_header_injection', 'test%0d%0aX-Injected: true'),
            ('log_injection', 'test%0d%0a[ERROR] Injected log entry'),
            ('code_injection', "eval('alert(1)')"),
            ('regex_dos', '((a+)+)+$'),
        ]
    )
    def test_user_security_sendemail_scene(self, desc, value):
        """发送邮箱验证码接口-安全测试(scene)"""
        res = self.user.sendemail(self.authorization, scene=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_user_required_sendemail_language(self, desc, value):
        """发送邮箱验证码接口-必填字段测试(language)"""
        if desc == 'missing':
            pl = {'pop_items': 'language'}
        else:
            pl = {'language': value}
        res = self.user.sendemail(authorization=self.authorization, **pl)
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
    def test_user_format_sendemail_language(self, desc, value):
        """发送邮箱验证码接口-数据格式测试(language)"""
        res = self.user.sendemail(self.authorization, language=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_user_boundary_sendemail_language(self, desc, value):
        """发送邮箱验证码接口-边界值测试(language)"""
        res = self.user.sendemail(self.authorization, language=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_user_scenario_sendemail_invalid_language(self):
        """发送邮箱验证码接口-场景异常-无效的language"""
        language = 'INVALID_VALUE'
        res = self.user.sendemail(self.authorization, language=language)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('sql_injection', "' OR '1'='1"),
            ('xss_script', "<script>alert('XSS')</script>"),
            ('xss_img', "<img src=x onerror=alert('XSS')>"),
            ('xss_iframe', "<iframe src=javascript:alert('XSS')></iframe>"),
            ('xml_injection', "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"),
            ('unicode_attack', '\\x00\\x01\\x02'),
            ('crlf_injection', 'test%0d%0aSet-Cookie: admin=true'),
            ('http_header_injection', 'test%0d%0aX-Injected: true'),
            ('log_injection', 'test%0d%0a[ERROR] Injected log entry'),
            ('code_injection', "eval('alert(1)')"),
            ('regex_dos', '((a+)+)+$'),
        ]
    )
    def test_user_security_sendemail_language(self, desc, value):
        """发送邮箱验证码接口-安全测试(language)"""
        res = self.user.sendemail(self.authorization, language=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"


    def test_user_positive_abtest_status_ok(self):
        """获取用户AB测试状态-正向用例"""
        res = self.user.abtest_status(self.authorization, status=2)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_user_positive_abtest_status1_ok(self):
        """获取用户AB测试状态-正向用例"""
        res = self.user.get_abtest_status(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.skip('接口已废弃')
    def test_user_positive_questionnaire_ok(self, getkidId):
        """提交问卷设置学习水平-正向用例"""
        kidId = getkidId['data'][0]['id']
        # 提交问卷设置学习水平
        res = self.user.questionnaire(self.authorization, kidId, learningLevel='L4')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == {'kidId': kidId, 'learningLevel': 'L4'}, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_user_permission_questionnaire(self, desc, value):
        """提交问卷设置学习水平-权限测试"""
        res = self.user.questionnaire(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_user_scenario_questionnaire_invalid_request(self, getkidId):
        """提交问卷设置学习水平-场景异常-无效的request"""
        kidId = getkidId['data'][0]['id']
        learningLevel = 'INVALID'
        res = self.user.questionnaire(self.authorization, kidId, learningLevel=learningLevel)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100006, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
        assert res['data'] == 'invalid parameter', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_user_positive_getLearningLevel_ok(self, getkidId):
        """获取孩子的学习水平-正向用例"""
        kidId = getkidId['data'][0]['id']
        # 获取孩子的学习水平
        res = self.user.getLearningLevel(self.authorization, kidId=kidId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == {'learningLevel': 'L1'}, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_user_permission_getLearningLevel(self, desc, value):
        """获取孩子的学习水平-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.user.getLearningLevel(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_user_positive_deleteDeleteaccount_ok(self):
        """删除用户账户-正向用例"""
        res = self.user.deleteDeleteaccount(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert 'data' in res, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_user_permission_deleteDeleteaccount(self, desc, value):
        """删除用户账户-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.user.deleteDeleteaccount(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_user_positive_getKids_ok(self):
        """获取当前用户的kids-正向用例"""
        res = self.user.getUserKids(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_user_permission_getUserKids(self, desc, value):
        """获取当前用户的kids-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.user.getUserKids(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_user_positive_sync_ok(self):
        """用户第三方登录后信息注册同步-正向用例"""
        res = self.user.registerInfo_sync(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

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
    def test_user_format_sync_req(self, desc, value, code, code_res):
        """用户第三方登录后信息注册同步-数据格式测试(req)"""
        try:
            res = self.user.registerInfo_sync(self.authorization, req=value, code=code)
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

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min_length', "", 500),
            ('max_length', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 500),
        ]
    )
    def test_user_boundary_sync_req(self, desc, value, code):
        """用户第三方登录后信息注册同步-边界值测试(req)"""
        res = self.user.registerInfo_sync(self.authorization, req=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_user_scenario_sync_invalid_req(self):
        """用户第三方登录后信息注册同步-场景异常-无效的req"""
        req = 'INVALID_VALUE'
        res = self.user.registerInfo_sync(self.authorization, req=req)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('sql_injection', "' OR '1'='1", 403, ''),
            ('xss_script', "<script>alert('XSS')</script>", 403, ''),
            ('xss_img', "<img src=x onerror=alert('XSS')>", 403, ''),
            ('xss_iframe', "<iframe src=javascript:alert('XSS')></iframe>", 403, ''),
            ('xml_injection', "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", 403, ''),
            ('unicode_attack', '\\x00\\x01\\x02', 200, 404),
            ('crlf_injection', 'test%0d%0aSet-Cookie: admin=true', 200, 404),
            ('code_injection', "eval('alert(1)')", 403, ''),
            ('regex_dos', '((a+)+)+$', 403, ''),
        ]
    )
    def test_user_security_sync_req(self, desc, value, code, code_res):
        """用户第三方登录后信息注册同步-安全测试(req)"""
        res = self.user.sync(self.authorization, req=value)
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
        else:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == code_res, f"接口返回状态码异常: 预期【{code_res}】，实际【{res['code']}】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【'not found'】，实际【{res['message']}】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【'not found'】，实际【{res['data']}】"

    @pytest.mark.parametrize('countryCode, phoneNumber, exist',
                             [
                                 (86, 18380143661, True), # 中国
                                 (86, 13541240009, False),  # 中国
                                 (1, 2025551234, False),   # 美国
                                 (44, 7700123456, False),  # 英国
                                 (81, 9012345678, False),  # 日本
                                 (82, 1012345678, False),  # 韩国
                                 (65, 91234567, False),    # 新加坡
                                 (91, 9876543210, False),  # 印度
                                 (62, 8123456789, False),  # 印度尼西亚
                                 (84, 912345678, False),  # 越南
                              ]
                             )
    def test_user_positive_checkPhone_ok(self, countryCode, phoneNumber, exist):
        """检测手机号是否已注册-正向用例"""
        time.sleep(3)   # 防止请求频率过高
        res = self.user.checkPhone(self.authorization, countryCode, phoneNumber)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['exist'] == exist, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    @pytest.mark.parametrize('dailyLessonLimit', [2, 3])
    def test_user_positive_dailyLessonLimit_ok(self, dailyLessonLimit):
        """设置孩子的每日课程数量限制-正向用例"""
        # 设置孩子的每日课程数量限制
        res = self.user.dailyLessonLimit(self.authorization, self.kid_id, dailyLessonLimit)
        assert res['data']['dailyLessonLimit'] == dailyLessonLimit
        assert res['data']['kidId'] == self.kid_id
        assert res['data']['kidName'] == self.kid_name
        # 获取孩子的每日课程数量限制，验证设置孩子的每日课程数量限制成功
        dailyLessonLimit_res = self.user.getDailyLessonLimitNew(self.authorization, self.kid_id)
        assert dailyLessonLimit_res['data']['dailyLessonLimit'] == dailyLessonLimit
        assert dailyLessonLimit_res['data']['kidId'] == self.kid_id
        assert dailyLessonLimit_res['data']['kidName'] == self.kid_name

    @pytest.mark.smoke
    @pytest.mark.parametrize('dailyLessonLimit', [1, 4])
    def test_user_positive_dailyLessonLimit_not_support(self, dailyLessonLimit):
        """非标准dailyLessonLimit数字设置孩子的每日课程数量限制-正向用例"""
        # 非标准dailyLessonLimit数字设置孩子的每日课程数量限制
        res = self.user.dailyLessonLimit(self.authorization, self.kid_id, dailyLessonLimit)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100006, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
        assert res['data'] == 'invalid parameter', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_user_positive_updatelanguage_ok(self):
        """更新用户语言偏好-正向用例"""
        res = self.user.updatelanguage(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['language'] == 'zh', f"接口返回data数据异常：{res['data']}"
        assert res['data']['userId'] == self.userId, f"接口返回data数据异常：{res['data']}"

    @pytest.fixture(scope="class")
    def kid_data_fixture(self):
        '''创建测试学生'''
        # 创建测试学生
        kid_name = 'dibo_test_kid' + self.now
        kid_id = self.user.createkid(self.authorization, kid_name)['data']['id']
        yield kid_id, kid_name
        # 删除测试学生
        self.user.deletekid(self.authorization, kid_id)

    @pytest.mark.smoke
    def test_user_positive_existingKidLevelInit_ok(self, kid_data_fixture):
        """老用户Kid学习等级初始化-只能去app上完成课程改变history的数量，没有接口可以实现，所以只能校验单接口"""
        '''
        1) 准备数据：kid 当前 learning_level=L1；learn_history 中有某个 NORMAL 课程完成次数≥3，且该课程 difficulty=L2（或更高）。
        2) 调用 POST /api/user/kid/{kidId}/existing-kid-level-init。
        3) 调用 GET /api/user/kid/{kidId}/learning-level 验证返回提升为 L2（updated=true）。
        '''
        kid_id, kid_name = kid_data_fixture
        init_res1 = self.user.existingKidLevelInit(self.authorization, kid_id)
        assert init_res1['data']['learningLevel'] == 'L1'
        assert init_res1['data']['updated'] == False

    @pytest.mark.smoke
    def test_user_positive_creategGuestUser_ok(self):
        """创建游客账户-正向用例"""
        # 创建游客账户
        res = self.user.creategGuestUser(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['message'] == 'success'
        assert res['data']['userInfo']['accountType'] == 'GUEST'
        assert res['data']['userInfo']['deviceId'] == '123456'
        # 通过deviceId获取用户信息
        res1 = self.user.userDevice(self.authorization)
        assert not res1['data']['isUser']
        assert res1['data']['isGuest']
        assert res1['data']['userInfo'] == res['data']['userInfo']

    def test_user_follow_flow(self):
        """
        用户关注完整流程测试
        步骤:
        1. 获取目标用户信息总览
        2. 检查是否已关注
        3. 关注用户
        4. 验证关注状态
        5. 取消关注
        6. 验证取消关注状态
        """
        # ========== Step 1: 获取目标用户信息总览 ==========
        profile_result = self.user.profileSummary(self.authorization, self.userId)

        assert profile_result.get('code') == 0, f"profileSummary 请求失败: {profile_result}"
        profile_data = profile_result.get('data')
        assert profile_data is not None, "用户信息总览 data 为空"

        # 校验返回字段
        assert 'userInfo' in profile_data, "缺少 userInfo 字段"
        assert 'joinAt' in profile_data, "缺少 joinAt 字段"
        assert 'storiesCount' in profile_data, "缺少 storiesCount 字段"
        assert 'favroured' in profile_data, "缺少 favroured 字段"
        assert 'beLiked' in profile_data, "缺少 beLiked 字段"

        # 校验 userInfo 结构
        user_info = profile_data['userInfo']
        assert user_info is not None, "userInfo 为空"
        assert 'userId' in user_info, "userInfo 缺少 userId"
        assert 'username' in user_info, "userInfo 缺少 username"

        # 校验 userId 匹配
        returned_user_id = user_info.get('userId')
        # userId 可能是字符串或数字
        assert str(returned_user_id) == str(self.target_user_id), \
            f"返回的 userId 不匹配: 期望 {self.target_user_id}, 实际 {returned_user_id}"

        # 校验统计数据类型
        assert isinstance(profile_data['storiesCount'], int), "storiesCount 应为整数"
        assert isinstance(profile_data['favroured'], int), "favroured 应为整数"
        assert isinstance(profile_data['beLiked'], int), "beLiked 应为整数"
        assert profile_data['storiesCount'] >= 0, "storiesCount 应 >= 0"
        assert profile_data['favroured'] >= 0, "favroured 应 >= 0"
        assert profile_data['beLiked'] >= 0, "beLiked 应 >= 0"

        # 校验 popularBooks (可能为空列表)
        if 'popularBooks' in profile_data:
            assert isinstance(profile_data['popularBooks'], list), "popularBooks 应为列表"

        # ========== Step 2: 检查是否已关注（初始状态）==========
        is_follow_result = self.user.isFollowUser(self.authorization, followed_id)

        assert is_follow_result.get('code') == 0, f"isFollowUser 请求失败: {is_follow_result}"
        is_followed_before = is_follow_result.get('data')
        assert isinstance(is_followed_before, bool), f"isFollow 返回值应为布尔类型: {type(is_followed_before)}"

        # ========== Step 3: 确保先取消关注（清理状态）==========
        if is_followed_before:
            self.user.deleteFollowUser(self.authorization, followed_id)

        # ========== Step 4: 关注用户 ==========
        follow_result = self.user.followUser(self.authorization, followed_id)

        assert follow_result.get('code') == 0, f"followUser 关注失败: {follow_result}"
        follow_data = follow_result.get('data')
        assert follow_data is not None, "关注返回 data 为空"

        # 返回被关注用户的信息
        assert 'id' in follow_data or 'userId' in follow_data, "返回数据缺少用户ID字段"
        # 验证返回的是目标用户
        followed_user_id = follow_data.get('id') or follow_data.get('userId')
        assert str(followed_user_id) == str(self.target_user_id), \
            f"返回的用户ID不匹配: 期望 {self.target_user_id}, 实际 {followed_user_id}"

        # ========== Step 5: 验证关注状态变为 True ==========
        is_follow_after = self.user.isFollowUser(self.authorization, followed_id)

        assert is_follow_after.get('code') == 0
        assert is_follow_after.get('data') is True, \
            f"关注后 isFollow 应为 True: {is_follow_after.get('data')}"

        # ========== Step 6: 取消关注 ==========
        unfollow_result = self.user.deleteFollowUser(self.authorization, followed_id)

        assert unfollow_result.get('code') == 0, f"deleteFollowUser 取消关注失败: {unfollow_result}"

        # ========== Step 7: 验证取消关注状态变为 False ==========
        is_follow_final = self.user.isFollowUser(self.authorization, followed_id)

        assert is_follow_final.get('code') == 0
        assert is_follow_final.get('data') is False, \
            f"取消关注后 isFollow 应为 False: {is_follow_final.get('data')}"

    def test_user_follow_flow11(self):
        """
        用户关注完整流程测试
        步骤:
        1. 获取目标用户信息总览
        2. 检查是否已关注
        3. 关注用户
        4. 验证关注状态
        5. 取消关注
        6. 验证取消关注状态
        """
        # ========== Step 1: 获取目标用户信息总览 ==========
        kid_res = self.kid.getKids(self.authorization)['data']
        for kid in kid_res:
            if kid['name'] == "Ss":
                kid_id = kid['id']
                break

        # 步骤1: 获取课程路径
        curriculum_paths = self.curriculum.get_curriculum_by_country(self.authorization, countryCode='JP')
        assert curriculum_paths["code"] == 200, f"获取课程路径失败: {curriculum_paths}"
        assert curriculum_paths["data"], "没有找到课程路径"

        # 选择第一个路径
        path_id = curriculum_paths["data"]["id"]

        # 步骤2: 获取该路径下的所有学习等级
        levels = self.curriculum.get_level_list(self.authorization, path_id)['data']
        for level in levels:
            if level['levelName'] == 'Level 2':
                level_id = level['id']
                key = 'NEW_MAP_S3_FIRST_ENTER_LEVEL_TIME'
                value = f'{level_id},1768708800000'
                profile_result = self.user.clientInteraction(self.authorization, key, kid_id, value=value)
                profile_data = profile_result.get('data')
                assert profile_data is not None, "用户信息总览 data 为空"
                break

        level_contents = self.curriculum.curriculum_level_contents(self.authorization, level_id, kid_id)['data'][0]
        part_len = len(level_contents['parts'])
        print(part_len)
