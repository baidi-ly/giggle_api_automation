import datetime
import sys
import os

from pandas import DataFrame

from test_case.page_api.admin.admin_activity_api import AdminActivityApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminActivity
class TestAdminActivity:

    def setup_class(self):
        self.activity = AdminActivityApi()
        self.authorization = self.activity.get_admin_authorization()[0]
        self.now = str(datetime.datetime.now())

    @pytest.fixture(scope="class")
    def create_activity(self):
        activity_name = "2025年夏季活动" + self.now
        pl = {
            "name": activity_name,
            "activityCode": "GENERAL",
            "startTime": "2025-08-12 08:00:00",
            "endTime": "2025-08-13 08:00:00",
            "status": "NOT_STARTED",
            "config": "{\"theme\":\"summer\"}"
        }
        activity_id = self.activity.create(self.authorization, **pl)['data']['id']
        yield activity_id
        # self.activity.delete_activity(self.authorization, activity_id)

    @pytest.fixture(scope="class")
    def create_task(self, create_activity):
        activity_id = create_activity
        task_name = "分享任务" + self.now
        pl = {
            "activityId": activity_id,
            "actionCode": "SHARE",
            "name": task_name
        }
        activity_task_id = self.activity.create_activity_task(self.authorization, **pl)['data']['id']
        yield activity_task_id
        self.activity.delete_activity_task(self.authorization, activity_task_id)

    @pytest.mark.smoke
    def test_activity_positive_create_ok(self):
        """创建活动-正向用例"""
        res = self.activity.create(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_activity_positive_create_activity_ok(self, create_activity):
        """创建活动-正向用例"""
        activity_id = create_activity
        task_name = "分享任务" + self.now
        pl = {
            "activityId": activity_id,
            "actionCode": "SHARE",
            "name": task_name
        }
        res = self.activity.create_activity_task(self.authorization, **pl)
        try:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
            activity_task_id = res['data']['id']
        finally:
            self.activity.delete_activity_task(self.authorization, activity_task_id)

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_activity_permission_create(self, desc, value):
        """创建活动-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.create(value)
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
    def test_activity_required_create_name(self, desc, value):
        """创建活动-必填字段测试(name)"""
        if desc == 'missing':
            pl = {'pop_items': 'name'}
        else:
            pl = {'name': value}
        res = self.activity.create(authorization=self.authorization, **pl)
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
    def test_activity_format_create_name(self, desc, value):
        """创建活动-数据格式测试(name)"""
        res = self.activity.create(self.authorization, name=value)
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
    def test_activity_boundary_create_name(self, desc, value):
        """创建活动-边界值测试(name)"""
        res = self.activity.create(self.authorization, name=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_activity_scenario_create_invalid_name(self):
        """创建活动-场景异常-无效的name"""
        name = 'INVALID_VALUE'
        res = self.activity.create(self.authorization, name=name)
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
    def test_activity_security_create_name(self, desc, value):
        """创建活动-安全测试(name)"""
        res = self.activity.create(self.authorization, name=value)
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
    def test_activity_required_create_activityCode(self, desc, value):
        """创建活动-必填字段测试(activityCode)"""
        if desc == 'missing':
            pl = {'pop_items': 'activityCode'}
        else:
            pl = {'activityCode': value}
        res = self.activity.create(authorization=self.authorization, **pl)
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
    def test_activity_format_create_activityCode(self, desc, value):
        """创建活动-数据格式测试(activityCode)"""
        res = self.activity.create(self.authorization, activityCode=value)
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
    def test_activity_boundary_create_activityCode(self, desc, value):
        """创建活动-边界值测试(activityCode)"""
        res = self.activity.create(self.authorization, activityCode=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_activity_scenario_create_invalid_activityCode(self):
        """创建活动-场景异常-无效的activityCode"""
        activityCode = 'INVALID_VALUE'
        res = self.activity.create(self.authorization, activityCode=activityCode)
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
    def test_activity_security_create_activityCode(self, desc, value):
        """创建活动-安全测试(activityCode)"""
        res = self.activity.create(self.authorization, activityCode=value)
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
    def test_activity_required_create_startTime(self, desc, value):
        """创建活动-必填字段测试(startTime)"""
        if desc == 'missing':
            pl = {'pop_items': 'startTime'}
        else:
            pl = {'startTime': value}
        res = self.activity.create(authorization=self.authorization, **pl)
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
    def test_activity_format_create_startTime(self, desc, value):
        """创建活动-数据格式测试(startTime)"""
        res = self.activity.create(self.authorization, startTime=value)
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
    def test_activity_boundary_create_startTime(self, desc, value):
        """创建活动-边界值测试(startTime)"""
        res = self.activity.create(self.authorization, startTime=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_activity_scenario_create_invalid_startTime(self):
        """创建活动-场景异常-无效的startTime"""
        startTime = 'INVALID_VALUE'
        res = self.activity.create(self.authorization, startTime=startTime)
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
    def test_activity_security_create_startTime(self, desc, value):
        """创建活动-安全测试(startTime)"""
        res = self.activity.create(self.authorization, startTime=value)
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
    def test_activity_required_create_endTime(self, desc, value):
        """创建活动-必填字段测试(endTime)"""
        if desc == 'missing':
            pl = {'pop_items': 'endTime'}
        else:
            pl = {'endTime': value}
        res = self.activity.create(authorization=self.authorization, **pl)
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
    def test_activity_format_create_endTime(self, desc, value):
        """创建活动-数据格式测试(endTime)"""
        res = self.activity.create(self.authorization, endTime=value)
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
    def test_activity_boundary_create_endTime(self, desc, value):
        """创建活动-边界值测试(endTime)"""
        res = self.activity.create(self.authorization, endTime=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_activity_scenario_create_invalid_endTime(self):
        """创建活动-场景异常-无效的endTime"""
        endTime = 'INVALID_VALUE'
        res = self.activity.create(self.authorization, endTime=endTime)
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
    def test_activity_security_create_endTime(self, desc, value):
        """创建活动-安全测试(endTime)"""
        res = self.activity.create(self.authorization, endTime=value)
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
    def test_activity_required_create_config(self, desc, value):
        """创建活动-必填字段测试(config)"""
        if desc == 'missing':
            pl = {'pop_items': 'config'}
        else:
            pl = {'config': value}
        res = self.activity.create(authorization=self.authorization, **pl)
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
    def test_activity_format_create_config(self, desc, value):
        """创建活动-数据格式测试(config)"""
        res = self.activity.create(self.authorization, config=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_activity_scenario_create_invalid_config(self):
        """创建活动-场景异常-无效的config"""
        config = 'INVALID_VALUE'
        res = self.activity.create(self.authorization, config=config)
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
    def test_activity_required_create_status(self, desc, value):
        """创建活动-必填字段测试(status)"""
        if desc == 'missing':
            pl = {'pop_items': 'status'}
        else:
            pl = {'status': value}
        res = self.activity.create(authorization=self.authorization, **pl)
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
    def test_activity_format_create_status(self, desc, value):
        """创建活动-数据格式测试(status)"""
        res = self.activity.create(self.authorization, status=value)
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
    def test_activity_boundary_create_status(self, desc, value):
        """创建活动-边界值测试(status)"""
        res = self.activity.create(self.authorization, status=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_activity_scenario_create_invalid_status(self):
        """创建活动-场景异常-无效的status"""
        status = 'INVALID_VALUE'
        res = self.activity.create(self.authorization, status=status)
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
    def test_activity_security_create_status(self, desc, value):
        """创建活动-安全测试(status)"""
        res = self.activity.create(self.authorization, status=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_activity_positive_activity_tags_ok(self):
        """获取标签列表-正向用例"""
        res = self.activity.activity_tags(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == [{'code': 'COURSE_COMPLETE', 'name': '完课'}], f"接口返回data数据异常：{res['data']}"

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
    def test_admin_activity_permission_activity_tags(self, desc, value):
        """获取标签列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.activity_tags(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_activity_positive_activity_general_tasks_ok(self):
        """获取通用活动任务定义列表-正向用例"""
        res = self.activity.activity_general_tasks(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
        task_names = DataFrame(res['data'])['name'].tolist()
        assert task_names == ['活动-扭蛋抽奖', '活动-扭蛋分享好友', '活动-扭蛋邀请好友', '活动-扭蛋完课'], "通用活动任务定义列表有误！"

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
    def test_admin_activity_permission_getList1(self, desc, value):
        """获取通用活动任务定义列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.activity.activity_general_tasks(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"