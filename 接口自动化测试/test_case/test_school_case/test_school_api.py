import pytest

from test_case.page_api.school.school_api import SchoolApi
from config import RunConfig

base_url = RunConfig.baseurl

class TestSchoolApi:
    """
    school 接口测试用例
    """

    def setup_class(self):
        self.school = SchoolApi()
        self.authorization = self.school.get_authorization()

    @pytest.mark.release
    def test_school_positive_school_class_ok(self):
        """创建班级-正向用例"""
        res = self.school.school_class(self.authorization)
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
    def test_school_permission_school_class(self, desc, value):
        """创建班级-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.school.school_class(value, code=401)
        # assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        # assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        # assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        # assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "''", 200),   # TODO
            ('null', None, 500),
        ]
    )
    def test_school_required_school_class_className(self, desc, value, code):
        """创建班级-必填字段测试(className)"""
        if desc == 'missing':
            pl = {'pop_items': 'className'}
        else:
            pl = {'className': value}
        res = self.school.school_class(authorization=self.authorization, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 200:
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
        else:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【internal server error】，实际【{res['message']}】"
            assert 'JSON parse error:' in res['data']['message'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('integer', 123),   # TODO
            ('float', 12.3),   # TODO
            ('boolean', True),  # TODO
            ('array', [1, 2, 3]),
            ('object', {'key': 'value'}),
            ('special_chars', '!@#$%^&*()_+-=[]{}|;\':",./<>?'),    # TODO
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
    def test_school_format_school_class_className(self, desc, value):
        """创建班级-数据格式测试(className)"""
        res = self.school.school_class(self.authorization, className=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),   # TODO
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_school_class_className(self, desc, value):
        """创建班级-边界值测试(className)"""
        res = self.school.school_class(self.authorization, className=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('sql_injection', "' OR '1'='1"),   # 研究一下每个注入情况应该是怎么返回
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
    def test_school_security_school_class_className(self, desc, value):
        """创建班级-安全测试(className)"""
        res = self.school.school_class(self.authorization, className=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_school_class_description(self, desc, value):
        """创建班级-必填字段测试(description)"""
        if desc == 'missing':
            pl = {'pop_items': 'description'}
        else:
            pl = {'description': value}
        res = self.school.school_class(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('integer', 123),   # TODO
            ('float', 12.3),  # TODO
            ('boolean', True),  # TODO
            ('array', [1, 2, 3]),  # TODO
            ('object', {'key': 'value'}),  # TODO
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
    def test_school_format_school_class_description(self, desc, value):
        """创建班级-数据格式测试(description)"""
        res = self.school.school_class(self.authorization, description=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_school_class_description(self, desc, value):
        """创建班级-边界值测试(description)"""
        res = self.school.school_class(self.authorization, description=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_security_school_class_description(self, desc, value):
        """创建班级-安全测试(description)"""
        res = self.school.school_class(self.authorization, description=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_school_class_grade(self, desc, value):
        """创建班级-必填字段测试(grade)"""
        if desc == 'missing':
            pl = {'pop_items': 'grade'}
        else:
            pl = {'grade': value}
        res = self.school.school_class(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),  # TODO
            ('float', 12.34),  # TODO
            ('boolean', True),  # TODO
            ('negative', -123),  # TODO
            ('array', [1, 2, 3]),  # TODO
            ('object', {"key": "value"}),  # TODO
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '"😀🎉🚀"')
        ]
    )
    def test_school_format_school_class_grade(self, desc, value):
        """创建班级-数据格式测试(grade)"""
        res = self.school.school_class(self.authorization, grade=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),  # TODO
            ('zero', 0),  # TODO
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_school_class_grade(self, desc, value):
        """创建班级-边界值测试(grade)"""
        res = self.school.school_class(self.authorization, grade=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_school_class_invalid_grade(self):
        """创建班级-场景异常-无效的grade"""
        grade = 999999999
        res = self.school.school_class(self.authorization, grade=grade)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_school_class_subject(self, desc, value):
        """创建班级-必填字段测试(subject)"""
        if desc == 'missing':
            pl = {'pop_items': 'subject'}
        else:
            pl = {'subject': value}
        res = self.school.school_class(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('integer', 123),   # TODO
            ('float', 12.3),   # TODO
            ('boolean', True),   # TODO
            ('array', [1, 2, 3]),   # TODO
            ('object', {'key': 'value'}),   # TODO
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
    def test_school_format_school_class_subject(self, desc, value):
        """创建班级-数据格式测试(subject)"""
        res = self.school.school_class(self.authorization, subject=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_school_class_subject(self, desc, value):
        """创建班级-边界值测试(subject)"""
        res = self.school.school_class(self.authorization, subject=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_security_school_class_subject(self, desc, value):
        """创建班级-安全测试(subject)"""
        res = self.school.school_class(self.authorization, subject=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_positive_getList_ok(self):
        """获取用户的班级列表-正向用例"""
        res = self.school.getList(self.authorization)
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
    def test_school_permission_getList(self, desc, value):
        """获取用户的班级列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.school.getList(value, code=401)
        if res:
            assert res['code'] == 401, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'] == 'The token was expected to have 3 parts, but got 0.', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('integer', 123),
            ('float', 12.34),
            ('array', [1, 2, 3]),   #  TODO
            ('object', {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '😀🎉🚀'),
            ('long_string', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_school_format_getList_all(self, desc, value):
        """获取用户的班级列表-数据格式测试(all)"""
        res = self.school.getList(self.authorization, all=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_getList_invalid_all(self):
        """获取用户的班级列表-场景异常-无效的all"""
        all = 'INVALID_VALUE'
        res = self.school.getList(self.authorization, all=all)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('boolean', True),
            ('float', 12.34),
            ('array', [1, 2, 3]),  # TODO
            ('object', {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '😀🎉🚀'),
            ('negative', -123),
            ('long_string', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_school_format_getList_page(self, desc, value):
        """获取用户的班级列表-数据格式测试(page)"""
        res = self.school.getList(self.authorization, page=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_getList_page(self, desc, value):
        """获取用户的班级列表-边界值测试(page)"""
        res = self.school.getList(self.authorization, page=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_getList_invalid_page(self):
        """获取用户的班级列表-场景异常-无效的page"""
        page = 999999999
        res = self.school.getList(self.authorization, page=page)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('float', 12.34),
            ('boolean', True),
            ('negative', -123),
            ('array', [1, 2, 3]),   # TODO
            ('object', {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '😀🎉🚀'),
            ('long_string', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_school_format_getList_size(self, desc, value):
        """获取用户的班级列表-数据格式测试(size)"""
        res = self.school.getList(self.authorization, size=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_getList_size(self, desc, value):
        """获取用户的班级列表-边界值测试(size)"""
        res = self.school.getList(self.authorization, size=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_getList_invalid_size(self):
        """获取用户的班级列表-场景异常-无效的size"""
        size = 147
        res = self.school.getList(self.authorization, size=size)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_positive_putAuto_ok(self):
        """更新班级信息-正向用例"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        pl = {
            "className": 'dibo.test',
            "imageUrl": res["imageUrl"],
            "room": res["room"],
            "subject": res["subject"],
            "teacherUserId": 1
        }
        res = self.school.putAuto(self.authorization, classId=res["id"], **pl)
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
    def test_school_permission_putAuto(self, desc, value):
        """更新班级信息-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.school.getList(self.authorization)['data']['content'][0]
        pl = {
            "className": 'dibo.test',
            "imageUrl": res["imageUrl"],
            "room": res["room"],
            "subject": res["subject"],
            "teacherUserId": 1
        }
        res = self.school.putAuto(value, classId=res["id"], code=401, **pl)
        if res:
            assert res['code'] == 401, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'] == 'The token was expected to have 3 parts, but got 0.', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto_classId(self, desc, value):
        """更新班级信息-必填字段测试(classId)"""
        if desc == 'missing':
            pl = {'pop_items': 'classId'}
        else:
            pl = {'classId': value}
        res = self.school.putAuto(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', '"abc"'),
            ('float', 12.34),
            ('boolean', True),
            ('negative', -123),
            ('array', [1, 2, 3]),
            ('object', {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji',  '😀🎉🚀'),
            ('long_string', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_school_format_putAuto_classId(self, desc, value):
        """更新班级信息-数据格式测试(classId)"""
        res = self.school.putAuto(self.authorization, classId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),   # TODO
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_putAuto_classId(self, desc, value):
        """更新班级信息-边界值测试(classId)"""
        res = self.school.putAuto(self.authorization, classId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_putAuto_invalid_classId(self):
        """更新班级信息-场景异常-无效的classId"""
        classId = 999999999
        res = self.school.putAuto(self.authorization, classId=classId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),    # TODO
            ('null', None),
        ]
    )
    def test_school_required_putAuto_className(self, desc, value):
        """更新班级信息-必填字段测试(className)"""
        if desc == 'missing':
            pl = {'pop_items': 'className'}
        else:
            pl = {'className': value}
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(authorization=self.authorization, classId=res["id"], **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('integer', 123),  # TODO
            ('float', 12.3),  # TODO
            ('boolean', True),  # TODO
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
    def test_school_format_putAuto_className(self, desc, value):
        """更新班级信息-数据格式测试(className)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], className=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto_className(self, desc, value):
        """更新班级信息-边界值测试(className)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], className=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_security_putAuto_className(self, desc, value):
        """更新班级信息-安全测试(className)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], className=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto_imageUrl(self, desc, value):
        """更新班级信息-必填字段测试(imageUrl)"""
        if desc == 'missing':
            pl = {'pop_items': 'imageUrl'}
        else:
            pl = {'imageUrl': value}
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('integer', 123),
            ('float', 12.3),
            ('boolean', True),
            ('array', [1, 2, 3]),   # TODO
            ('object', {'key': 'value'}),  # TODO
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
    def test_school_format_putAuto_imageUrl(self, desc, value):
        """更新班级信息-数据格式测试(imageUrl)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], imageUrl=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto_imageUrl(self, desc, value):
        """更新班级信息-边界值测试(imageUrl)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], imageUrl=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_putAuto_invalid_imageUrl(self):
        """更新班级信息-场景异常-无效的imageUrl"""
        imageUrl = 'INVALID_VALUE'
        res = self.school.putAuto(self.authorization, imageUrl=imageUrl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_security_putAuto_imageUrl(self, desc, value):
        """更新班级信息-安全测试(imageUrl)"""
        res = self.school.putAuto(self.authorization, imageUrl=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto_room(self, desc, value):
        """更新班级信息-必填字段测试(room)"""
        if desc == 'missing':
            pl = {'pop_items': 'room'}
        else:
            pl = {'room': value}
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('integer', 123),   # TODO
            ('float', 12.3),    # TODO
            ('boolean', True),  # TODO
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
    def test_school_format_putAuto_room(self, desc, value):
        """更新班级信息-数据格式测试(room)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], room=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto_room(self, desc, value):
        """更新班级信息-边界值测试(room)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], room=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_security_putAuto_room(self, desc, value):
        """更新班级信息-安全测试(room)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], room=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto_subject(self, desc, value):
        """更新班级信息-必填字段测试(subject)"""
        if desc == 'missing':
            pl = {'pop_items': 'subject'}
        else:
            pl = {'subject': value}
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('integer', 123),   # TODO
            ('float', 12.3),   # TODO
            ('boolean', True),   # TODO
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
    def test_school_format_putAuto_subject(self, desc, value):
        """更新班级信息-数据格式测试(subject)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], subject=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto_subject(self, desc, value):
        """更新班级信息-边界值测试(subject)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], subject=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_putAuto_invalid_subject(self):
        """更新班级信息-场景异常-无效的subject"""
        subject = 'INVALID_VALUE'
        res = self.school.putAuto(self.authorization, subject=subject)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_security_putAuto_subject(self, desc, value):
        """更新班级信息-安全测试(subject)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], subject=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),    # TODO : 这个字段可以为None, 可以不传入，但是传入''就会报错
            ('null', None),
        ]
    )
    def test_school_required_putAuto_teacherUserId(self, desc, value):
        """更新班级信息-必填字段测试(teacherUserId)"""
        if desc == 'missing':
            pl = {'pop_items': 'teacherUserId'}
        else:
            pl = {'teacherUserId': value}
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('float', 12.34),   # TODO
            ('boolean', True),
            ('negative',-123),  # TODO
            ('array', [1, 2, 3]),
            ('object',  {"key": "value"}),
            ('special_chars', "!@#$%^&*()"),
            ('emoji',  '"😀🎉🚀"'),
            ('long_string','"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_school_format_putAuto_teacherUserId(self, desc, value):
        """更新班级信息-数据格式测试(teacherUserId)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], teacherUserId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),    # TODO
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_putAuto_teacherUserId(self, desc, value):
        """更新班级信息-边界值测试(teacherUserId)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], teacherUserId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_putAuto_invalid_teacherUserId(self):
        """更新班级信息-场景异常-无效的teacherUserId"""
        teacherUserId = 999999999
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], teacherUserId=teacherUserId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_positive_deleteAuto_ok(self):
        """删除班级-正向用例"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.deleteAuto(self.authorization, classId=res["id"])
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
    def test_school_permission_deleteAuto(self, desc, value):
        """删除班级-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.deleteAuto(value, classId=classId, code=401)
        if res:
            assert res['code'] == 401, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'] == 'The token was expected to have 3 parts, but got 0.', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_deleteAuto_classId(self, desc, value):
        """删除班级-必填字段测试(classId)"""
        if desc == 'missing':
            pl = {'pop_items': 'classId'}
        else:
            pl = {'classId': value}
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.deleteAuto(self.authorization, classId=classId, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),  # TODO
            ('float', 12.34),  # TODO
            ('boolean',True),  # TODO
            ('negative', -123),  # TODO
            ('array', [1, 2, 3]),  # TODO
            ('object', {"key": "value"}),  # TODO
            ('special_chars',  '!@#$%^&*()'),  # TODO
            ('emoji',  '😀🎉🚀'),
            ('long_string', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]  # TODO
    )
    def test_school_format_deleteAuto_classId(self, desc, value):
        """删除班级-数据格式测试(classId)"""
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.deleteAuto(self.authorization, classId=classId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),  # TODO
            ('zero', 0),  # TODO
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_deleteAuto_classId(self, desc, value):
        """删除班级-边界值测试(classId)"""
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.deleteAuto(self.authorization, classId=classId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_deleteAuto_invalid_classId(self):
        """删除班级-场景异常-无效的classId"""
        classId = 999999999
        res = self.school.deleteAuto(self.authorization, classId=classId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_positive_batch_ok(self):
        """批量添加学生-正向用例"""
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.batch(self.authorization, classId)
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
    def test_school_permission_batch(self, desc, value):
        """批量添加学生-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.batch(value, classId, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),   # TODO
            ('null', None),   # TODO
        ]
    )
    def test_school_required_batch_classId(self, desc, value):
        """批量添加学生-必填字段测试(classId)"""
        if desc == 'missing':
            pl = {'pop_items': 'classId'}
        else:
            pl = {}
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.batch(self.authorization, classId, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string',  'abc'),
            ('float', 12.34),
            ('boolean', True),
            ('negative', -123),
            ('array', [1, 2, 3]),
            ('object', {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '😀🎉🚀'),
            ('long_string',  '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_school_format_batch_classId(self, desc, value):
        """批量添加学生-数据格式测试(classId)"""
        res = self.school.batch(self.authorization, classId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_batch_classId(self, desc, value):
        """批量添加学生-边界值测试(classId)"""
        res = self.school.batch(self.authorization, value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_batch_invalid_classId(self):
        """批量添加学生-场景异常-无效的classId"""
        classId = 999999999
        res = self.school.batch(self.authorization, classId=classId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_batch_studentNames(self, desc, value):
        """批量添加学生-必填字段测试(studentNames)"""
        if desc == 'missing':
            pl = {'pop_items': 'studentNames'}
        else:
            pl = {'studentNames': value}
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.batch(self.authorization, classId, code=500, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_format_batch_studentNames(self, desc, value):
        """批量添加学生-数据格式测试(studentNames)"""
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.batch(self.authorization, classId, studentNames=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_batch_invalid_studentNames(self):
        """批量添加学生-场景异常-无效的studentNames"""
        studentNames = ['1','2','3','4']    # TODO
        classId = self.school.getList(self.authorization)['data']['content'][5]['id']
        res = self.school.batch(self.authorization, classId, studentNames=studentNames, code=500)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_positive_getStudents_ok(self):
        """获取班级学生列表-正向用例"""
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.getStudents(self.authorization, classId)
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
    def test_school_permission_getStudents(self, desc, value):
        """获取班级学生列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.getStudents(value, classId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_positive_putAuto1_ok(self):
        """更新学生信息-正向用例"""
        res = self.school.putAuto1(self.authorization)
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
    def test_school_permission_putAuto1(self, desc, value):
        """更新学生信息-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.school.putAuto1(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto1_studentId(self, desc, value):
        """更新学生信息-必填字段测试(studentId)"""
        if desc == 'missing':
            pl = {'pop_items': 'studentId'}
        else:
            pl = {'studentId': value}
        res = self.school.putAuto1(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_putAuto1_studentId(self, desc, value):
        """更新学生信息-边界值测试(studentId)"""
        res = self.school.putAuto1(self.authorization, studentId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_putAuto1_invalid_studentId(self):
        """更新学生信息-场景异常-无效的studentId"""
        studentId = 999999999
        res = self.school.putAuto1(self.authorization, studentId=studentId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto1_avatarUrl(self, desc, value):
        """更新学生信息-必填字段测试(avatarUrl)"""
        if desc == 'missing':
            pl = {'pop_items': 'avatarUrl'}
        else:
            pl = {'avatarUrl': value}
        res = self.school.putAuto1(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_format_putAuto1_avatarUrl(self, desc, value):
        """更新学生信息-数据格式测试(avatarUrl)"""
        res = self.school.putAuto1(self.authorization, avatarUrl=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto1_avatarUrl(self, desc, value):
        """更新学生信息-边界值测试(avatarUrl)"""
        res = self.school.putAuto1(self.authorization, avatarUrl=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_putAuto1_invalid_avatarUrl(self):
        """更新学生信息-场景异常-无效的avatarUrl"""
        avatarUrl = 'INVALID_VALUE'
        res = self.school.putAuto1(self.authorization, avatarUrl=avatarUrl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_security_putAuto1_avatarUrl(self, desc, value):
        """更新学生信息-安全测试(avatarUrl)"""
        res = self.school.putAuto1(self.authorization, avatarUrl=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto1_studentName(self, desc, value):
        """更新学生信息-必填字段测试(studentName)"""
        if desc == 'missing':
            pl = {'pop_items': 'studentName'}
        else:
            pl = {'studentName': value}
        res = self.school.putAuto1(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_format_putAuto1_studentName(self, desc, value):
        """更新学生信息-数据格式测试(studentName)"""
        res = self.school.putAuto1(self.authorization, studentName=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto1_studentName(self, desc, value):
        """更新学生信息-边界值测试(studentName)"""
        res = self.school.putAuto1(self.authorization, studentName=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_putAuto1_invalid_studentName(self):
        """更新学生信息-场景异常-无效的studentName"""
        studentName = 'INVALID_VALUE'
        res = self.school.putAuto1(self.authorization, studentName=studentName)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_security_putAuto1_studentName(self, desc, value):
        """更新学生信息-安全测试(studentName)"""
        res = self.school.putAuto1(self.authorization, studentName=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto1_username(self, desc, value):
        """更新学生信息-必填字段测试(username)"""
        if desc == 'missing':
            pl = {'pop_items': 'username'}
        else:
            pl = {'username': value}
        res = self.school.putAuto1(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_format_putAuto1_username(self, desc, value):
        """更新学生信息-数据格式测试(username)"""
        res = self.school.putAuto1(self.authorization, username=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto1_username(self, desc, value):
        """更新学生信息-边界值测试(username)"""
        res = self.school.putAuto1(self.authorization, username=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_putAuto1_invalid_username(self):
        """更新学生信息-场景异常-无效的username"""
        username = 'INVALID_VALUE'
        res = self.school.putAuto1(self.authorization, username=username)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_security_putAuto1_username(self, desc, value):
        """更新学生信息-安全测试(username)"""
        res = self.school.putAuto1(self.authorization, username=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"



    @pytest.mark.release
    def test_school_positive_deleteAuto1_ok(self):
        """删除学生-正向用例"""
        res = self.school.deleteAuto1(self.authorization)
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
    def test_school_permission_deleteAuto1(self, desc, value):
        """删除学生-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.school.deleteAuto1(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_deleteAuto1_studentId(self, desc, value):
        """删除学生-必填字段测试(studentId)"""
        if desc == 'missing':
            pl = {'pop_items': 'studentId'}
        else:
            pl = {'studentId': value}
        res = self.school.deleteAuto1(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"


    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_deleteAuto1_studentId(self, desc, value):
        """删除学生-边界值测试(studentId)"""
        res = self.school.deleteAuto1(self.authorization, studentId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_school_scenario_deleteAuto1_invalid_studentId(self):
        """删除学生-场景异常-无效的studentId"""
        studentId = 999999999
        res = self.school.deleteAuto1(self.authorization, studentId=studentId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"



    @pytest.mark.release
    def test_school_positive_lesson_ok(self):
        """创建课堂-正向用例"""
        res = self.school.lesson(self.authorization)
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
    def test_school_permission_lesson(self, desc, value):
        """创建课堂-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.school.lesson(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', ""),
            ('null', None),
        ]
    )
    def test_school_required_lesson_classId(self, desc, value):
        """创建课堂-必填字段测试(classId)"""
        if desc == 'missing':
            pl = {'pop_items': 'classId'}
        else:
            pl = {'classId': value}
        res = self.school.lesson(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
        assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
        assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 500),
            ('boolean', True, 500),
            ('negative', -123, 500),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '😀🎉🚀', 500),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_lesson_classId(self, desc, value, code):
        """创建课堂-数据格式测试(classId)"""
        res = self.school.lesson(self.authorization, classId=value, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
        assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
        assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_lesson_classId(self, desc, value, code):
        """创建课堂-边界值测试(classId)"""
        res = self.school.lesson(self.authorization, classId=value, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
        assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
        assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    def test_school_scenario_lesson_invalid_classId(self):
        """创建课堂-场景异常-无效的classId"""
        classId = 999999999
        res = self.school.lesson(self.authorization, classId=classId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', ""),
            ('null', None),
        ]
    )
    def test_school_required_lesson_lessonName(self, desc, value):
        """创建课堂-必填字段测试(lessonName)"""
        if desc == 'missing':
            pl = {'pop_items': 'lessonName'}
        else:
            pl = {'lessonName': value}
        res = self.school.lesson(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
        assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
        assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('float', 12.34),
            ('boolean', True),
            ('negative', -123),
            ('array', [1, 2, 3]),
            ('object', {'key': 'value'}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '😀🎉🚀'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
        ]
    )
    def test_school_format_lesson_lessonName(self, desc, value):
        """创建课堂-数据格式测试(lessonName)"""
        res = self.school.lesson(self.authorization, lessonName=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
        assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
        assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_lesson_lessonName(self, desc, value):
        """创建课堂-边界值测试(lessonName)"""
        res = self.school.lesson(self.authorization, lessonName=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
        assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
        assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    def test_school_scenario_lesson_invalid_lessonName(self):
        """创建课堂-场景异常-无效的lessonName"""
        lessonName = 'INVALID_VALUE'
        res = self.school.lesson(self.authorization, lessonName=lessonName)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_security_lesson_lessonName(self, desc, value):
        """创建课堂-安全测试(lessonName)"""
        res = self.school.lesson(self.authorization, lessonName=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', ""),
            ('null', None),
        ]
    )
    def test_school_required_lesson_teachingLanguage(self, desc, value):
        """创建课堂-必填字段测试(teachingLanguage)"""
        if desc == 'missing':
            pl = {'pop_items': 'teachingLanguage'}
        else:
            pl = {'teachingLanguage': value}
        res = self.school.lesson(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
        assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
        assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('float', 12.34),
            ('boolean', True),
            ('negative', -123),
            ('array', [1, 2, 3]),
            ('object', {'key': 'value'}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '😀🎉🚀'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
        ]
    )
    def test_school_format_lesson_teachingLanguage(self, desc, value):
        """创建课堂-数据格式测试(teachingLanguage)"""
        res = self.school.lesson(self.authorization, teachingLanguage=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
        assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
        assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_lesson_teachingLanguage(self, desc, value):
        """创建课堂-边界值测试(teachingLanguage)"""
        res = self.school.lesson(self.authorization, teachingLanguage=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
        assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
        assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    def test_school_scenario_lesson_invalid_teachingLanguage(self):
        """创建课堂-场景异常-无效的teachingLanguage"""
        teachingLanguage = 'INVALID_VALUE'
        res = self.school.lesson(self.authorization, teachingLanguage=teachingLanguage)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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
    def test_school_security_lesson_teachingLanguage(self, desc, value):
        """创建课堂-安全测试(teachingLanguage)"""
        res = self.school.lesson(self.authorization, teachingLanguage=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', ""),
            ('null', None),
        ]
    )
    def test_school_required_lesson_resources(self, desc, value):
        """创建课堂-必填字段测试(resources)"""
        if desc == 'missing':
            pl = {'pop_items': 'resources'}
        else:
            pl = {'resources': value}
        res = self.school.lesson(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
        assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
        assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('float', 12.34),
            ('boolean', True),
            ('negative', -123),
            ('array', [1, 2, 3]),
            ('object', {'key': 'value'}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '😀🎉🚀'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
        ]
    )
    def test_school_format_lesson_resources(self, desc, value):
        """创建课堂-数据格式测试(resources)"""
        res = self.school.lesson(self.authorization, resources=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
        assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
        assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_lesson_resources(self, desc, value):
        """创建课堂-边界值测试(resources)"""
        res = self.school.lesson(self.authorization, resources=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
        assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
        assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    def test_school_scenario_lesson_invalid_resources(self):
        """创建课堂-场景异常-无效的resources"""
        resources = 'INVALID_VALUE'
        res = self.school.lesson(self.authorization, resources=resources)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

