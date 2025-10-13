import pytest

from test_case.page_api.school.school_api import SchoolApi
from config import RunConfig

base_url = RunConfig.baseurl

class TestSchoolApi:
    """
    school 鎺ュ彛娴嬭瘯鐢ㄤ緥
    """

    def setup_class(self):
        self.school = SchoolApi()
        self.authorization = self.school.get_authorization()

    def test_school_positive_school_class_ok(self):
        """鍒涘缓鐝骇-姝ｅ悜鐢ㄤ緥"""
        res = self.school.school_class(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鍒涘缓鐝骇-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.school_class(value, code=401)
        # assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        # assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        # assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        # assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "''", 200),   # TODO
            ('null', None, 500),
        ]
    )
    def test_school_required_school_class_className(self, desc, value, code):
        """鍒涘缓鐝骇-蹇呭～瀛楁娴嬭瘯(className)"""
        if desc == 'missing':
            pl = {'pop_items': 'className'}
        else:
            pl = {'className': value}
        res = self.school.school_class(authorization=self.authorization, code=code, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 200:
            assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
        else:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恑nternal server error銆戯紝瀹為檯銆恵res['message']}銆?
            assert 'JSON parse error:' in res['data']['message'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '涓枃娴嬭瘯'),
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
        """鍒涘缓鐝骇-鏁版嵁鏍煎紡娴嬭瘯(className)"""
        res = self.school.school_class(self.authorization, className=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),   # TODO
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_school_class_className(self, desc, value):
        """鍒涘缓鐝骇-杈圭晫鍊兼祴璇?className)"""
        res = self.school.school_class(self.authorization, className=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('sql_injection', "' OR '1'='1"),   # 鐮旂┒涓€涓嬫瘡涓敞鍏ユ儏鍐靛簲璇ユ槸鎬庝箞杩斿洖
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
        """鍒涘缓鐝骇-瀹夊叏娴嬭瘯(className)"""
        res = self.school.school_class(self.authorization, className=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_school_class_description(self, desc, value):
        """鍒涘缓鐝骇-蹇呭～瀛楁娴嬭瘯(description)"""
        if desc == 'missing':
            pl = {'pop_items': 'description'}
        else:
            pl = {'description': value}
        res = self.school.school_class(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '涓枃娴嬭瘯'),
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
        """鍒涘缓鐝骇-鏁版嵁鏍煎紡娴嬭瘯(description)"""
        res = self.school.school_class(self.authorization, description=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_school_class_description(self, desc, value):
        """鍒涘缓鐝骇-杈圭晫鍊兼祴璇?description)"""
        res = self.school.school_class(self.authorization, description=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鍒涘缓鐝骇-瀹夊叏娴嬭瘯(description)"""
        res = self.school.school_class(self.authorization, description=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_school_class_grade(self, desc, value):
        """鍒涘缓鐝骇-蹇呭～瀛楁娴嬭瘯(grade)"""
        if desc == 'missing':
            pl = {'pop_items': 'grade'}
        else:
            pl = {'grade': value}
        res = self.school.school_class(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '"馃榾馃帀馃殌"')
        ]
    )
    def test_school_format_school_class_grade(self, desc, value):
        """鍒涘缓鐝骇-鏁版嵁鏍煎紡娴嬭瘯(grade)"""
        res = self.school.school_class(self.authorization, grade=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),  # TODO
            ('zero', 0),  # TODO
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_school_class_grade(self, desc, value):
        """鍒涘缓鐝骇-杈圭晫鍊兼祴璇?grade)"""
        res = self.school.school_class(self.authorization, grade=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_school_class_invalid_grade(self):
        """鍒涘缓鐝骇-鍦烘櫙寮傚父-鏃犳晥鐨刧rade"""
        grade = 999999999
        res = self.school.school_class(self.authorization, grade=grade)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_school_class_subject(self, desc, value):
        """鍒涘缓鐝骇-蹇呭～瀛楁娴嬭瘯(subject)"""
        if desc == 'missing':
            pl = {'pop_items': 'subject'}
        else:
            pl = {'subject': value}
        res = self.school.school_class(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '涓枃娴嬭瘯'),
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
        """鍒涘缓鐝骇-鏁版嵁鏍煎紡娴嬭瘯(subject)"""
        res = self.school.school_class(self.authorization, subject=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_school_class_subject(self, desc, value):
        """鍒涘缓鐝骇-杈圭晫鍊兼祴璇?subject)"""
        res = self.school.school_class(self.authorization, subject=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鍒涘缓鐝骇-瀹夊叏娴嬭瘯(subject)"""
        res = self.school.school_class(self.authorization, subject=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_positive_getList_ok(self):
        """鑾峰彇鐢ㄦ埛鐨勭彮绾у垪琛?姝ｅ悜鐢ㄤ緥"""
        res = self.school.getList(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鑾峰彇鐢ㄦ埛鐨勭彮绾у垪琛?鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.getList(value, code=401)
        if res:
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == 'The token was expected to have 3 parts, but got 0.', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('integer', 123),
            ('float', 12.34),
            ('array', [1, 2, 3]),   #  TODO
            ('object', {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_school_format_getList_all(self, desc, value):
        """鑾峰彇鐢ㄦ埛鐨勭彮绾у垪琛?鏁版嵁鏍煎紡娴嬭瘯(all)"""
        res = self.school.getList(self.authorization, all=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_getList_invalid_all(self):
        """鑾峰彇鐢ㄦ埛鐨勭彮绾у垪琛?鍦烘櫙寮傚父-鏃犳晥鐨刟ll"""
        all = 'INVALID_VALUE'
        res = self.school.getList(self.authorization, all=all)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('string', 'abc'),
            ('boolean', True),
            ('float', 12.34),
            ('array', [1, 2, 3]),  # TODO
            ('object', {"key": "value"}),
            ('special_chars', '!@#$%^&*()'),
            ('emoji', '馃榾馃帀馃殌'),
            ('negative', -123),
            ('long_string', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_school_format_getList_page(self, desc, value):
        """鑾峰彇鐢ㄦ埛鐨勭彮绾у垪琛?鏁版嵁鏍煎紡娴嬭瘯(page)"""
        res = self.school.getList(self.authorization, page=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_getList_page(self, desc, value):
        """鑾峰彇鐢ㄦ埛鐨勭彮绾у垪琛?杈圭晫鍊兼祴璇?page)"""
        res = self.school.getList(self.authorization, page=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_getList_invalid_page(self):
        """鑾峰彇鐢ㄦ埛鐨勭彮绾у垪琛?鍦烘櫙寮傚父-鏃犳晥鐨刾age"""
        page = 999999999
        res = self.school.getList(self.authorization, page=page)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_school_format_getList_size(self, desc, value):
        """鑾峰彇鐢ㄦ埛鐨勭彮绾у垪琛?鏁版嵁鏍煎紡娴嬭瘯(size)"""
        res = self.school.getList(self.authorization, size=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_getList_size(self, desc, value):
        """鑾峰彇鐢ㄦ埛鐨勭彮绾у垪琛?杈圭晫鍊兼祴璇?size)"""
        res = self.school.getList(self.authorization, size=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_getList_invalid_size(self):
        """鑾峰彇鐢ㄦ埛鐨勭彮绾у垪琛?鍦烘櫙寮傚父-鏃犳晥鐨剆ize"""
        size = 147
        res = self.school.getList(self.authorization, size=size)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_positive_putAuto_ok(self):
        """鏇存柊鐝骇淇℃伅-姝ｅ悜鐢ㄤ緥"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        pl = {
            "className": 'dibo.test',
            "imageUrl": res["imageUrl"],
            "room": res["room"],
            "subject": res["subject"],
            "teacherUserId": 1
        }
        res = self.school.putAuto(self.authorization, classId=res["id"], **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鏇存柊鐝骇淇℃伅-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
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
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == 'The token was expected to have 3 parts, but got 0.', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto_classId(self, desc, value):
        """鏇存柊鐝骇淇℃伅-蹇呭～瀛楁娴嬭瘯(classId)"""
        if desc == 'missing':
            pl = {'pop_items': 'classId'}
        else:
            pl = {'classId': value}
        res = self.school.putAuto(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji',  '馃榾馃帀馃殌'),
            ('long_string', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_school_format_putAuto_classId(self, desc, value):
        """鏇存柊鐝骇淇℃伅-鏁版嵁鏍煎紡娴嬭瘯(classId)"""
        res = self.school.putAuto(self.authorization, classId=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),   # TODO
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_putAuto_classId(self, desc, value):
        """鏇存柊鐝骇淇℃伅-杈圭晫鍊兼祴璇?classId)"""
        res = self.school.putAuto(self.authorization, classId=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_putAuto_invalid_classId(self):
        """鏇存柊鐝骇淇℃伅-鍦烘櫙寮傚父-鏃犳晥鐨刢lassId"""
        classId = 999999999
        res = self.school.putAuto(self.authorization, classId=classId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),    # TODO
            ('null', None),
        ]
    )
    def test_school_required_putAuto_className(self, desc, value):
        """鏇存柊鐝骇淇℃伅-蹇呭～瀛楁娴嬭瘯(className)"""
        if desc == 'missing':
            pl = {'pop_items': 'className'}
        else:
            pl = {'className': value}
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(authorization=self.authorization, classId=res["id"], **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '涓枃娴嬭瘯'),
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
        """鏇存柊鐝骇淇℃伅-鏁版嵁鏍煎紡娴嬭瘯(className)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], className=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto_className(self, desc, value):
        """鏇存柊鐝骇淇℃伅-杈圭晫鍊兼祴璇?className)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], className=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鏇存柊鐝骇淇℃伅-瀹夊叏娴嬭瘯(className)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], className=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto_imageUrl(self, desc, value):
        """鏇存柊鐝骇淇℃伅-蹇呭～瀛楁娴嬭瘯(imageUrl)"""
        if desc == 'missing':
            pl = {'pop_items': 'imageUrl'}
        else:
            pl = {'imageUrl': value}
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '涓枃娴嬭瘯'),
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
        """鏇存柊鐝骇淇℃伅-鏁版嵁鏍煎紡娴嬭瘯(imageUrl)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], imageUrl=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto_imageUrl(self, desc, value):
        """鏇存柊鐝骇淇℃伅-杈圭晫鍊兼祴璇?imageUrl)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], imageUrl=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_putAuto_invalid_imageUrl(self):
        """鏇存柊鐝骇淇℃伅-鍦烘櫙寮傚父-鏃犳晥鐨刬mageUrl"""
        imageUrl = 'INVALID_VALUE'
        res = self.school.putAuto(self.authorization, imageUrl=imageUrl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鏇存柊鐝骇淇℃伅-瀹夊叏娴嬭瘯(imageUrl)"""
        res = self.school.putAuto(self.authorization, imageUrl=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto_room(self, desc, value):
        """鏇存柊鐝骇淇℃伅-蹇呭～瀛楁娴嬭瘯(room)"""
        if desc == 'missing':
            pl = {'pop_items': 'room'}
        else:
            pl = {'room': value}
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '涓枃娴嬭瘯'),
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
        """鏇存柊鐝骇淇℃伅-鏁版嵁鏍煎紡娴嬭瘯(room)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], room=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto_room(self, desc, value):
        """鏇存柊鐝骇淇℃伅-杈圭晫鍊兼祴璇?room)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], room=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鏇存柊鐝骇淇℃伅-瀹夊叏娴嬭瘯(room)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], room=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto_subject(self, desc, value):
        """鏇存柊鐝骇淇℃伅-蹇呭～瀛楁娴嬭瘯(subject)"""
        if desc == 'missing':
            pl = {'pop_items': 'subject'}
        else:
            pl = {'subject': value}
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '涓枃娴嬭瘯'),
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
        """鏇存柊鐝骇淇℃伅-鏁版嵁鏍煎紡娴嬭瘯(subject)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], subject=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto_subject(self, desc, value):
        """鏇存柊鐝骇淇℃伅-杈圭晫鍊兼祴璇?subject)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], subject=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_putAuto_invalid_subject(self):
        """鏇存柊鐝骇淇℃伅-鍦烘櫙寮傚父-鏃犳晥鐨剆ubject"""
        subject = 'INVALID_VALUE'
        res = self.school.putAuto(self.authorization, subject=subject)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鏇存柊鐝骇淇℃伅-瀹夊叏娴嬭瘯(subject)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], subject=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),    # TODO : 杩欎釜瀛楁鍙互涓篘one, 鍙互涓嶄紶鍏ワ紝浣嗘槸浼犲叆''灏变細鎶ラ敊
            ('null', None),
        ]
    )
    def test_school_required_putAuto_teacherUserId(self, desc, value):
        """鏇存柊鐝骇淇℃伅-蹇呭～瀛楁娴嬭瘯(teacherUserId)"""
        if desc == 'missing':
            pl = {'pop_items': 'teacherUserId'}
        else:
            pl = {'teacherUserId': value}
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji',  '"馃榾馃帀馃殌"'),
            ('long_string','"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_school_format_putAuto_teacherUserId(self, desc, value):
        """鏇存柊鐝骇淇℃伅-鏁版嵁鏍煎紡娴嬭瘯(teacherUserId)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], teacherUserId=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),    # TODO
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_putAuto_teacherUserId(self, desc, value):
        """鏇存柊鐝骇淇℃伅-杈圭晫鍊兼祴璇?teacherUserId)"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], teacherUserId=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_putAuto_invalid_teacherUserId(self):
        """鏇存柊鐝骇淇℃伅-鍦烘櫙寮傚父-鏃犳晥鐨則eacherUserId"""
        teacherUserId = 999999999
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.putAuto(self.authorization, classId=res["id"], teacherUserId=teacherUserId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_positive_deleteAuto_ok(self):
        """鍒犻櫎鐝骇-姝ｅ悜鐢ㄤ緥"""
        res = self.school.getList(self.authorization)['data']['content'][0]
        res = self.school.deleteAuto(self.authorization, classId=res["id"])
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鍒犻櫎鐝骇-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.deleteAuto(value, classId=classId, code=401)
        if res:
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == 'The token was expected to have 3 parts, but got 0.', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_deleteAuto_classId(self, desc, value):
        """鍒犻櫎鐝骇-蹇呭～瀛楁娴嬭瘯(classId)"""
        if desc == 'missing':
            pl = {'pop_items': 'classId'}
        else:
            pl = {'classId': value}
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.deleteAuto(self.authorization, classId=classId, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji',  '馃榾馃帀馃殌'),
            ('long_string', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]  # TODO
    )
    def test_school_format_deleteAuto_classId(self, desc, value):
        """鍒犻櫎鐝骇-鏁版嵁鏍煎紡娴嬭瘯(classId)"""
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.deleteAuto(self.authorization, classId=classId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),  # TODO
            ('zero', 0),  # TODO
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_deleteAuto_classId(self, desc, value):
        """鍒犻櫎鐝骇-杈圭晫鍊兼祴璇?classId)"""
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.deleteAuto(self.authorization, classId=classId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_deleteAuto_invalid_classId(self):
        """鍒犻櫎鐝骇-鍦烘櫙寮傚父-鏃犳晥鐨刢lassId"""
        classId = 999999999
        res = self.school.deleteAuto(self.authorization, classId=classId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_positive_batch_ok(self):
        """鎵归噺娣诲姞瀛︾敓-姝ｅ悜鐢ㄤ緥"""
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.batch(self.authorization, classId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鎵归噺娣诲姞瀛︾敓-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.batch(value, classId, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),   # TODO
            ('null', None),   # TODO
        ]
    )
    def test_school_required_batch_classId(self, desc, value):
        """鎵归噺娣诲姞瀛︾敓-蹇呭～瀛楁娴嬭瘯(classId)"""
        if desc == 'missing':
            pl = {'pop_items': 'classId'}
        else:
            pl = {}
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.batch(self.authorization, classId, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string',  '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_school_format_batch_classId(self, desc, value):
        """鎵归噺娣诲姞瀛︾敓-鏁版嵁鏍煎紡娴嬭瘯(classId)"""
        res = self.school.batch(self.authorization, classId=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_batch_classId(self, desc, value):
        """鎵归噺娣诲姞瀛︾敓-杈圭晫鍊兼祴璇?classId)"""
        res = self.school.batch(self.authorization, value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_batch_invalid_classId(self):
        """鎵归噺娣诲姞瀛︾敓-鍦烘櫙寮傚父-鏃犳晥鐨刢lassId"""
        classId = 999999999
        res = self.school.batch(self.authorization, classId=classId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_batch_studentNames(self, desc, value):
        """鎵归噺娣诲姞瀛︾敓-蹇呭～瀛楁娴嬭瘯(studentNames)"""
        if desc == 'missing':
            pl = {'pop_items': 'studentNames'}
        else:
            pl = {'studentNames': value}
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.batch(self.authorization, classId, code=500, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '涓枃娴嬭瘯'),
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
        """鎵归噺娣诲姞瀛︾敓-鏁版嵁鏍煎紡娴嬭瘯(studentNames)"""
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.batch(self.authorization, classId, studentNames=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_batch_invalid_studentNames(self):
        """鎵归噺娣诲姞瀛︾敓-鍦烘櫙寮傚父-鏃犳晥鐨剆tudentNames"""
        studentNames = ['1','2','3','4']    # TODO
        classId = self.school.getList(self.authorization)['data']['content'][5]['id']
        res = self.school.batch(self.authorization, classId, studentNames=studentNames, code=500)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_positive_getStudents_ok(self):
        """鑾峰彇鐝骇瀛︾敓鍒楄〃-姝ｅ悜鐢ㄤ緥"""
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.getStudents(self.authorization, classId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鑾峰彇鐝骇瀛︾敓鍒楄〃-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        classId = self.school.getList(self.authorization)['data']['content'][1]['id']
        res = self.school.getStudents(value, classId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_positive_putAuto1_ok(self):
        """鏇存柊瀛︾敓淇℃伅-姝ｅ悜鐢ㄤ緥"""
        res = self.school.putAuto1(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鏇存柊瀛︾敓淇℃伅-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.putAuto1(value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto1_studentId(self, desc, value):
        """鏇存柊瀛︾敓淇℃伅-蹇呭～瀛楁娴嬭瘯(studentId)"""
        if desc == 'missing':
            pl = {'pop_items': 'studentId'}
        else:
            pl = {'studentId': value}
        res = self.school.putAuto1(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_putAuto1_studentId(self, desc, value):
        """鏇存柊瀛︾敓淇℃伅-杈圭晫鍊兼祴璇?studentId)"""
        res = self.school.putAuto1(self.authorization, studentId=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_putAuto1_invalid_studentId(self):
        """鏇存柊瀛︾敓淇℃伅-鍦烘櫙寮傚父-鏃犳晥鐨剆tudentId"""
        studentId = 999999999
        res = self.school.putAuto1(self.authorization, studentId=studentId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto1_avatarUrl(self, desc, value):
        """鏇存柊瀛︾敓淇℃伅-蹇呭～瀛楁娴嬭瘯(avatarUrl)"""
        if desc == 'missing':
            pl = {'pop_items': 'avatarUrl'}
        else:
            pl = {'avatarUrl': value}
        res = self.school.putAuto1(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '涓枃娴嬭瘯'),
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
        """鏇存柊瀛︾敓淇℃伅-鏁版嵁鏍煎紡娴嬭瘯(avatarUrl)"""
        res = self.school.putAuto1(self.authorization, avatarUrl=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto1_avatarUrl(self, desc, value):
        """鏇存柊瀛︾敓淇℃伅-杈圭晫鍊兼祴璇?avatarUrl)"""
        res = self.school.putAuto1(self.authorization, avatarUrl=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_putAuto1_invalid_avatarUrl(self):
        """鏇存柊瀛︾敓淇℃伅-鍦烘櫙寮傚父-鏃犳晥鐨刟vatarUrl"""
        avatarUrl = 'INVALID_VALUE'
        res = self.school.putAuto1(self.authorization, avatarUrl=avatarUrl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鏇存柊瀛︾敓淇℃伅-瀹夊叏娴嬭瘯(avatarUrl)"""
        res = self.school.putAuto1(self.authorization, avatarUrl=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto1_studentName(self, desc, value):
        """鏇存柊瀛︾敓淇℃伅-蹇呭～瀛楁娴嬭瘯(studentName)"""
        if desc == 'missing':
            pl = {'pop_items': 'studentName'}
        else:
            pl = {'studentName': value}
        res = self.school.putAuto1(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '涓枃娴嬭瘯'),
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
        """鏇存柊瀛︾敓淇℃伅-鏁版嵁鏍煎紡娴嬭瘯(studentName)"""
        res = self.school.putAuto1(self.authorization, studentName=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto1_studentName(self, desc, value):
        """鏇存柊瀛︾敓淇℃伅-杈圭晫鍊兼祴璇?studentName)"""
        res = self.school.putAuto1(self.authorization, studentName=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_putAuto1_invalid_studentName(self):
        """鏇存柊瀛︾敓淇℃伅-鍦烘櫙寮傚父-鏃犳晥鐨剆tudentName"""
        studentName = 'INVALID_VALUE'
        res = self.school.putAuto1(self.authorization, studentName=studentName)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鏇存柊瀛︾敓淇℃伅-瀹夊叏娴嬭瘯(studentName)"""
        res = self.school.putAuto1(self.authorization, studentName=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_putAuto1_username(self, desc, value):
        """鏇存柊瀛︾敓淇℃伅-蹇呭～瀛楁娴嬭瘯(username)"""
        if desc == 'missing':
            pl = {'pop_items': 'username'}
        else:
            pl = {'username': value}
        res = self.school.putAuto1(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
            ('emoji', '馃榾馃帀馃殌'),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            ('unicode', '涓枃娴嬭瘯'),
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
        """鏇存柊瀛︾敓淇℃伅-鏁版嵁鏍煎紡娴嬭瘯(username)"""
        res = self.school.putAuto1(self.authorization, username=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('shortest', ""),
            ('longest', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_school_boundary_putAuto1_username(self, desc, value):
        """鏇存柊瀛︾敓淇℃伅-杈圭晫鍊兼祴璇?username)"""
        res = self.school.putAuto1(self.authorization, username=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_putAuto1_invalid_username(self):
        """鏇存柊瀛︾敓淇℃伅-鍦烘櫙寮傚父-鏃犳晥鐨剈sername"""
        username = 'INVALID_VALUE'
        res = self.school.putAuto1(self.authorization, username=username)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鏇存柊瀛︾敓淇℃伅-瀹夊叏娴嬭瘯(username)"""
        res = self.school.putAuto1(self.authorization, username=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"



    def test_school_positive_deleteAuto1_ok(self):
        """鍒犻櫎瀛︾敓-姝ｅ悜鐢ㄤ緥"""
        res = self.school.deleteAuto1(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鍒犻櫎瀛︾敓-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.deleteAuto1(value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', "''"),
            ('null', None),
        ]
    )
    def test_school_required_deleteAuto1_studentId(self, desc, value):
        """鍒犻櫎瀛︾敓-蹇呭～瀛楁娴嬭瘯(studentId)"""
        if desc == 'missing':
            pl = {'pop_items': 'studentId'}
        else:
            pl = {'studentId': value}
        res = self.school.deleteAuto1(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"


    @pytest.mark.parametrize(
        'desc, value',
        [
            ('min', -2147483648),
            ('zero', 0),
            ('max', 2147483647),
        ]
    )
    def test_school_boundary_deleteAuto1_studentId(self, desc, value):
        """鍒犻櫎瀛︾敓-杈圭晫鍊兼祴璇?studentId)"""
        res = self.school.deleteAuto1(self.authorization, studentId=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_scenario_deleteAuto1_invalid_studentId(self):
        """鍒犻櫎瀛︾敓-鍦烘櫙寮傚父-鏃犳晥鐨剆tudentId"""
        studentId = 999999999
        res = self.school.deleteAuto1(self.authorization, studentId=studentId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    def test_school_positive_lesson_ok(self):
        """鍒涘缓璇惧爞-姝ｅ悜鐢ㄤ緥"""
        res = self.school.lesson(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鍒涘缓璇惧爞-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.lesson(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', ""),
            ('null', None),
        ]
    )
    def test_school_required_lesson_classId(self, desc, value):
        """鍒涘缓璇惧爞-蹇呭～瀛楁娴嬭瘯(classId)"""
        if desc == 'missing':
            pl = {'pop_items': 'classId'}
        else:
            pl = {'classId': value}
        res = self.school.lesson(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 100132, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00132銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'Class not found', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?Class not found'銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'] == 'Class not found', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€?Class not found'銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_lesson_classId(self, desc, value, code):
        """鍒涘缓璇惧爞-鏁版嵁鏍煎紡娴嬭瘯(classId)"""
        res = self.school.lesson(self.authorization, classId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_lesson_classId(self, desc, value, code):
        """鍒涘缓璇惧爞-杈圭晫鍊兼祴璇?classId)"""
        res = self.school.lesson(self.authorization, classId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_lesson_invalid_classId(self):
        """鍒涘缓璇惧爞-鍦烘櫙寮傚父-鏃犳晥鐨刢lassId"""
        classId = 999999999
        res = self.school.lesson(self.authorization, classId=classId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', ""),
            ('null', None),
        ]
    )
    def test_school_required_lesson_lessonName(self, desc, value):
        """鍒涘缓璇惧爞-蹇呭～瀛楁娴嬭瘯(lessonName)"""
        if desc == 'missing':
            pl = {'pop_items': 'lessonName'}
        else:
            pl = {'lessonName': value}
        res = self.school.lesson(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

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
            ('emoji', '馃榾馃帀馃殌', 500),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_lesson_lessonName(self, desc, value, code):
        """鍒涘缓璇惧爞-鏁版嵁鏍煎紡娴嬭瘯(lessonName)"""
        res = self.school.lesson(self.authorization, lessonName=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_lesson_lessonName(self, desc, value, code):
        """鍒涘缓璇惧爞-杈圭晫鍊兼祴璇?lessonName)"""
        res = self.school.lesson(self.authorization, lessonName=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_lesson_invalid_lessonName(self):
        """鍒涘缓璇惧爞-鍦烘櫙寮傚父-鏃犳晥鐨刲essonName"""
        lessonName = 'INVALID_VALUE'
        res = self.school.lesson(self.authorization, lessonName=lessonName)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鍒涘缓璇惧爞-瀹夊叏娴嬭瘯(lessonName)"""
        res = self.school.lesson(self.authorization, lessonName=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', ""),
            ('null', None),
        ]
    )
    def test_school_required_lesson_teachingLanguage(self, desc, value):
        """鍒涘缓璇惧爞-蹇呭～瀛楁娴嬭瘯(teachingLanguage)"""
        if desc == 'missing':
            pl = {'pop_items': 'teachingLanguage'}
        else:
            pl = {'teachingLanguage': value}
        res = self.school.lesson(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

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
            ('emoji', '馃榾馃帀馃殌', 500),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_lesson_teachingLanguage(self, desc, value, code):
        """鍒涘缓璇惧爞-鏁版嵁鏍煎紡娴嬭瘯(teachingLanguage)"""
        res = self.school.lesson(self.authorization, teachingLanguage=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_lesson_teachingLanguage(self, desc, value, code):
        """鍒涘缓璇惧爞-杈圭晫鍊兼祴璇?teachingLanguage)"""
        res = self.school.lesson(self.authorization, teachingLanguage=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_lesson_invalid_teachingLanguage(self):
        """鍒涘缓璇惧爞-鍦烘櫙寮傚父-鏃犳晥鐨則eachingLanguage"""
        teachingLanguage = 'INVALID_VALUE'
        res = self.school.lesson(self.authorization, teachingLanguage=teachingLanguage)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
        """鍒涘缓璇惧爞-瀹夊叏娴嬭瘯(teachingLanguage)"""
        res = self.school.lesson(self.authorization, teachingLanguage=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('missing',  'missing'),
            ('empty', ""),
            ('null', None),
        ]
    )
    def test_school_required_lesson_resources(self, desc, value):
        """鍒涘缓璇惧爞-蹇呭～瀛楁娴嬭瘯(resources)"""
        if desc == 'missing':
            pl = {'pop_items': 'resources'}
        else:
            pl = {'resources': value}
        res = self.school.lesson(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

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
            ('emoji', '馃榾馃帀馃殌', 500),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_lesson_resources(self, desc, value, code):
        """鍒涘缓璇惧爞-鏁版嵁鏍煎紡娴嬭瘯(resources)"""
        res = self.school.lesson(self.authorization, resources=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_lesson_resources(self, desc, value, code):
        """鍒涘缓璇惧爞-杈圭晫鍊兼祴璇?resources)"""
        res = self.school.lesson(self.authorization, resources=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_lesson_invalid_resources(self):
        """鍒涘缓璇惧爞-鍦烘櫙寮傚父-鏃犳晥鐨剅esources"""
        resources = 'INVALID_VALUE'
        res = self.school.lesson(self.authorization, resources=resources)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"



    def test_school_positive_lesson_details_ok(self):
        """鑾峰彇璇惧爞璇︽儏-姝ｅ悜鐢ㄤ緥"""
        res = self.school.lesson_details(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_lesson_details(self, desc, value):
        """鑾峰彇璇惧爞璇︽儏-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.lesson_details(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_lesson_details_lessonId(self, desc, value, code):
        """鑾峰彇璇惧爞璇︽儏-蹇呭～瀛楁娴嬭瘯(lessonId)"""
        if desc == 'missing':
            pl = {'pop_items': 'lessonId'}
        else:
            pl = {'lessonId': value}
        res = self.school.lesson_details(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_lesson_details_lessonId(self, desc, value, code):
        """鑾峰彇璇惧爞璇︽儏-鏁版嵁鏍煎紡娴嬭瘯(lessonId)"""
        res = self.school.lesson_details(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_lesson_details_lessonId(self, desc, value, code):
        """鑾峰彇璇惧爞璇︽儏-杈圭晫鍊兼祴璇?lessonId)"""
        res = self.school.lesson_details(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_lesson_details_invalid_lessonId(self):
        """鑾峰彇璇惧爞璇︽儏-鍦烘櫙寮傚父-鏃犳晥鐨刲essonId"""
        lessonId = 999999999
        res = self.school.lesson_details(self.authorization, lessonId=lessonId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"



    def test_school_positive_lesson_details1_ok(self):
        """鏇存柊璇惧爞淇℃伅-姝ｅ悜鐢ㄤ緥"""
        res = self.school.lesson_details1(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_lesson_details1(self, desc, value):
        """鏇存柊璇惧爞淇℃伅-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.lesson_details1(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_lesson_details1_lessonId(self, desc, value, code):
        """鏇存柊璇惧爞淇℃伅-蹇呭～瀛楁娴嬭瘯(lessonId)"""
        if desc == 'missing':
            pl = {'pop_items': 'lessonId'}
        else:
            pl = {'lessonId': value}
        res = self.school.lesson_details1(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_lesson_details1_lessonId(self, desc, value, code):
        """鏇存柊璇惧爞淇℃伅-鏁版嵁鏍煎紡娴嬭瘯(lessonId)"""
        res = self.school.lesson_details1(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_lesson_details1_lessonId(self, desc, value, code):
        """鏇存柊璇惧爞淇℃伅-杈圭晫鍊兼祴璇?lessonId)"""
        res = self.school.lesson_details1(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_lesson_details1_invalid_lessonId(self):
        """鏇存柊璇惧爞淇℃伅-鍦烘櫙寮傚父-鏃犳晥鐨刲essonId"""
        lessonId = 999999999
        res = self.school.lesson_details1(self.authorization, lessonId=lessonId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"



    def test_school_positive_lesson_details2_ok(self):
        """鍒犻櫎璇惧爞-姝ｅ悜鐢ㄤ緥"""
        res = self.school.lesson_details2(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_lesson_details2(self, desc, value):
        """鍒犻櫎璇惧爞-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.lesson_details2(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_lesson_details2_lessonId(self, desc, value, code):
        """鍒犻櫎璇惧爞-蹇呭～瀛楁娴嬭瘯(lessonId)"""
        if desc == 'missing':
            pl = {'pop_items': 'lessonId'}
        else:
            pl = {'lessonId': value}
        res = self.school.lesson_details2(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_lesson_details2_lessonId(self, desc, value, code):
        """鍒犻櫎璇惧爞-鏁版嵁鏍煎紡娴嬭瘯(lessonId)"""
        res = self.school.lesson_details2(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_lesson_details2_lessonId(self, desc, value, code):
        """鍒犻櫎璇惧爞-杈圭晫鍊兼祴璇?lessonId)"""
        res = self.school.lesson_details2(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_lesson_details2_invalid_lessonId(self):
        """鍒犻櫎璇惧爞-鍦烘櫙寮傚父-鏃犳晥鐨刲essonId"""
        lessonId = 999999999
        res = self.school.lesson_details2(self.authorization, lessonId=lessonId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"



    def test_school_positive_getLessons_ok(self):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-姝ｅ悜鐢ㄤ緥"""
        res = self.school.getLessons(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_getLessons(self, desc, value):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.getLessons(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_getLessons_classId(self, desc, value, code):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-蹇呭～瀛楁娴嬭瘯(classId)"""
        if desc == 'missing':
            pl = {'pop_items': 'classId'}
        else:
            pl = {'classId': value}
        res = self.school.getLessons(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_getLessons_classId(self, desc, value, code):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-鏁版嵁鏍煎紡娴嬭瘯(classId)"""
        res = self.school.getLessons(self.authorization, classId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_getLessons_classId(self, desc, value, code):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-杈圭晫鍊兼祴璇?classId)"""
        res = self.school.getLessons(self.authorization, classId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_getLessons_invalid_classId(self):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-鍦烘櫙寮傚父-鏃犳晥鐨刢lassId"""
        classId = 999999999
        res = self.school.getLessons(self.authorization, classId=classId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_getLessons_keyword(self, desc, value, code):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-鏁版嵁鏍煎紡娴嬭瘯(keyword)"""
        res = self.school.getLessons(self.authorization, keyword=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_getLessons_keyword(self, desc, value, code):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-杈圭晫鍊兼祴璇?keyword)"""
        res = self.school.getLessons(self.authorization, keyword=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_getLessons_invalid_keyword(self):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-鍦烘櫙寮傚父-鏃犳晥鐨刱eyword"""
        keyword = 'INVALID_VALUE'
        res = self.school.getLessons(self.authorization, keyword=keyword)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
    def test_school_security_getLessons_keyword(self, desc, value):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-瀹夊叏娴嬭瘯(keyword)"""
        res = self.school.getLessons(self.authorization, keyword=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_getLessons_page(self, desc, value, code):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-鏁版嵁鏍煎紡娴嬭瘯(page)"""
        res = self.school.getLessons(self.authorization, page=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_getLessons_page(self, desc, value, code):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-杈圭晫鍊兼祴璇?page)"""
        res = self.school.getLessons(self.authorization, page=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_getLessons_invalid_page(self):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-鍦烘櫙寮傚父-鏃犳晥鐨刾age"""
        page = 999999999
        res = self.school.getLessons(self.authorization, page=page)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_getLessons_size(self, desc, value, code):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-鏁版嵁鏍煎紡娴嬭瘯(size)"""
        res = self.school.getLessons(self.authorization, size=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_getLessons_size(self, desc, value, code):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-杈圭晫鍊兼祴璇?size)"""
        res = self.school.getLessons(self.authorization, size=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_getLessons_invalid_size(self):
        """鑾峰彇鐝骇璇惧爞鍒楄〃-鍦烘櫙寮傚父-鏃犳晥鐨剆ize"""
        size = 999999999
        res = self.school.getLessons(self.authorization, size=size)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"



    def test_school_positive_groups_ok(self):
        """鍒涘缓瀛︾敓鍒嗙粍-姝ｅ悜鐢ㄤ緥"""
        res = self.school.groups(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_groups(self, desc, value):
        """鍒涘缓瀛︾敓鍒嗙粍-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.groups(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_groups_lessonId(self, desc, value, code):
        """鍒涘缓瀛︾敓鍒嗙粍-蹇呭～瀛楁娴嬭瘯(lessonId)"""
        if desc == 'missing':
            pl = {'pop_items': 'lessonId'}
        else:
            pl = {'lessonId': value}
        res = self.school.groups(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_groups_lessonId(self, desc, value, code):
        """鍒涘缓瀛︾敓鍒嗙粍-鏁版嵁鏍煎紡娴嬭瘯(lessonId)"""
        res = self.school.groups(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_groups_lessonId(self, desc, value, code):
        """鍒涘缓瀛︾敓鍒嗙粍-杈圭晫鍊兼祴璇?lessonId)"""
        res = self.school.groups(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_groups_invalid_lessonId(self):
        """鍒涘缓瀛︾敓鍒嗙粍-鍦烘櫙寮傚父-鏃犳晥鐨刲essonId"""
        lessonId = 999999999
        res = self.school.groups(self.authorization, lessonId=lessonId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"



    def test_school_positive_getResources_ok(self):
        """鑾峰彇璇惧爞瀛︿範璧勬簮-姝ｅ悜鐢ㄤ緥"""
        res = self.school.getResources(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_getResources(self, desc, value):
        """鑾峰彇璇惧爞瀛︿範璧勬簮-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.getResources(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_getResources_lessonId(self, desc, value, code):
        """鑾峰彇璇惧爞瀛︿範璧勬簮-蹇呭～瀛楁娴嬭瘯(lessonId)"""
        if desc == 'missing':
            pl = {'pop_items': 'lessonId'}
        else:
            pl = {'lessonId': value}
        res = self.school.getResources(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_getResources_lessonId(self, desc, value, code):
        """鑾峰彇璇惧爞瀛︿範璧勬簮-鏁版嵁鏍煎紡娴嬭瘯(lessonId)"""
        res = self.school.getResources(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_getResources_lessonId(self, desc, value, code):
        """鑾峰彇璇惧爞瀛︿範璧勬簮-杈圭晫鍊兼祴璇?lessonId)"""
        res = self.school.getResources(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_getResources_invalid_lessonId(self):
        """鑾峰彇璇惧爞瀛︿範璧勬簮-鍦烘櫙寮傚父-鏃犳晥鐨刲essonId"""
        lessonId = 999999999
        res = self.school.getResources(self.authorization, lessonId=lessonId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"



    def test_school_positive_qrcode_details_ok(self):
        """鑾峰彇璇惧爞灏忕粍浜岀淮鐮?姝ｅ悜鐢ㄤ緥"""
        res = self.school.qrcode_details(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_qrcode_details(self, desc, value):
        """鑾峰彇璇惧爞灏忕粍浜岀淮鐮?鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.qrcode_details(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_qrcode_details_groupSeqNo(self, desc, value, code):
        """鑾峰彇璇惧爞灏忕粍浜岀淮鐮?蹇呭～瀛楁娴嬭瘯(groupSeqNo)"""
        if desc == 'missing':
            pl = {'pop_items': 'groupSeqNo'}
        else:
            pl = {'groupSeqNo': value}
        res = self.school.qrcode_details(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_qrcode_details_groupSeqNo(self, desc, value, code):
        """鑾峰彇璇惧爞灏忕粍浜岀淮鐮?鏁版嵁鏍煎紡娴嬭瘯(groupSeqNo)"""
        res = self.school.qrcode_details(self.authorization, groupSeqNo=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_qrcode_details_groupSeqNo(self, desc, value, code):
        """鑾峰彇璇惧爞灏忕粍浜岀淮鐮?杈圭晫鍊兼祴璇?groupSeqNo)"""
        res = self.school.qrcode_details(self.authorization, groupSeqNo=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_qrcode_details_invalid_groupSeqNo(self):
        """鑾峰彇璇惧爞灏忕粍浜岀淮鐮?鍦烘櫙寮傚父-鏃犳晥鐨刧roupSeqNo"""
        groupSeqNo = 999999999
        res = self.school.qrcode_details(self.authorization, groupSeqNo=groupSeqNo)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_qrcode_details_lessonId(self, desc, value, code):
        """鑾峰彇璇惧爞灏忕粍浜岀淮鐮?蹇呭～瀛楁娴嬭瘯(lessonId)"""
        if desc == 'missing':
            pl = {'pop_items': 'lessonId'}
        else:
            pl = {'lessonId': value}
        res = self.school.qrcode_details(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_qrcode_details_lessonId(self, desc, value, code):
        """鑾峰彇璇惧爞灏忕粍浜岀淮鐮?鏁版嵁鏍煎紡娴嬭瘯(lessonId)"""
        res = self.school.qrcode_details(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_qrcode_details_lessonId(self, desc, value, code):
        """鑾峰彇璇惧爞灏忕粍浜岀淮鐮?杈圭晫鍊兼祴璇?lessonId)"""
        res = self.school.qrcode_details(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_qrcode_details_invalid_lessonId(self):
        """鑾峰彇璇惧爞灏忕粍浜岀淮鐮?鍦烘櫙寮傚父-鏃犳晥鐨刲essonId"""
        lessonId = 999999999
        res = self.school.qrcode_details(self.authorization, lessonId=lessonId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"



    def test_school_positive_qrcode_ok(self):
        """瀛︾敓鎵爜鐧诲綍-姝ｅ悜鐢ㄤ緥"""
        res = self.school.qrcode(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_qrcode(self, desc, value):
        """瀛︾敓鎵爜鐧诲綍-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.qrcode(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"



    def test_school_positive_getNormalcourse_ok(self):
        """Normal璇剧▼璧勬簮鍒楄〃-姝ｅ悜鐢ㄤ緥"""
        res = self.school.getNormalcourse(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_getNormalcourse(self, desc, value):
        """Normal璇剧▼璧勬簮鍒楄〃-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.getNormalcourse(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_getNormalcourse_keyword(self, desc, value, code):
        """Normal璇剧▼璧勬簮鍒楄〃-鏁版嵁鏍煎紡娴嬭瘯(keyword)"""
        res = self.school.getNormalcourse(self.authorization, keyword=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_getNormalcourse_keyword(self, desc, value, code):
        """Normal璇剧▼璧勬簮鍒楄〃-杈圭晫鍊兼祴璇?keyword)"""
        res = self.school.getNormalcourse(self.authorization, keyword=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_getNormalcourse_invalid_keyword(self):
        """Normal璇剧▼璧勬簮鍒楄〃-鍦烘櫙寮傚父-鏃犳晥鐨刱eyword"""
        keyword = 'INVALID_VALUE'
        res = self.school.getNormalcourse(self.authorization, keyword=keyword)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
    def test_school_security_getNormalcourse_keyword(self, desc, value):
        """Normal璇剧▼璧勬簮鍒楄〃-瀹夊叏娴嬭瘯(keyword)"""
        res = self.school.getNormalcourse(self.authorization, keyword=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_getNormalcourse_page(self, desc, value, code):
        """Normal璇剧▼璧勬簮鍒楄〃-鏁版嵁鏍煎紡娴嬭瘯(page)"""
        res = self.school.getNormalcourse(self.authorization, page=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_getNormalcourse_page(self, desc, value, code):
        """Normal璇剧▼璧勬簮鍒楄〃-杈圭晫鍊兼祴璇?page)"""
        res = self.school.getNormalcourse(self.authorization, page=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_getNormalcourse_invalid_page(self):
        """Normal璇剧▼璧勬簮鍒楄〃-鍦烘櫙寮傚父-鏃犳晥鐨刾age"""
        page = 999999999
        res = self.school.getNormalcourse(self.authorization, page=page)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_getNormalcourse_size(self, desc, value, code):
        """Normal璇剧▼璧勬簮鍒楄〃-鏁版嵁鏍煎紡娴嬭瘯(size)"""
        res = self.school.getNormalcourse(self.authorization, size=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_getNormalcourse_size(self, desc, value, code):
        """Normal璇剧▼璧勬簮鍒楄〃-杈圭晫鍊兼祴璇?size)"""
        res = self.school.getNormalcourse(self.authorization, size=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_getNormalcourse_invalid_size(self):
        """Normal璇剧▼璧勬簮鍒楄〃-鍦烘櫙寮傚父-鏃犳晥鐨剆ize"""
        size = 999999999
        res = self.school.getNormalcourse(self.authorization, size=size)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"



    def test_school_positive_getQuiz_ok(self):
        """娴嬮獙鍒楄〃-姝ｅ悜鐢ㄤ緥"""
        res = self.school.getQuiz(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_getQuiz(self, desc, value):
        """娴嬮獙鍒楄〃-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.getQuiz(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_getQuiz_keyword(self, desc, value, code):
        """娴嬮獙鍒楄〃-鏁版嵁鏍煎紡娴嬭瘯(keyword)"""
        res = self.school.getQuiz(self.authorization, keyword=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_getQuiz_keyword(self, desc, value, code):
        """娴嬮獙鍒楄〃-杈圭晫鍊兼祴璇?keyword)"""
        res = self.school.getQuiz(self.authorization, keyword=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_getQuiz_invalid_keyword(self):
        """娴嬮獙鍒楄〃-鍦烘櫙寮傚父-鏃犳晥鐨刱eyword"""
        keyword = 'INVALID_VALUE'
        res = self.school.getQuiz(self.authorization, keyword=keyword)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

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
    def test_school_security_getQuiz_keyword(self, desc, value):
        """娴嬮獙鍒楄〃-瀹夊叏娴嬭瘯(keyword)"""
        res = self.school.getQuiz(self.authorization, keyword=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_getQuiz_page(self, desc, value, code):
        """娴嬮獙鍒楄〃-鏁版嵁鏍煎紡娴嬭瘯(page)"""
        res = self.school.getQuiz(self.authorization, page=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_getQuiz_page(self, desc, value, code):
        """娴嬮獙鍒楄〃-杈圭晫鍊兼祴璇?page)"""
        res = self.school.getQuiz(self.authorization, page=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_getQuiz_invalid_page(self):
        """娴嬮獙鍒楄〃-鍦烘櫙寮傚父-鏃犳晥鐨刾age"""
        page = 999999999
        res = self.school.getQuiz(self.authorization, page=page)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_getQuiz_size(self, desc, value, code):
        """娴嬮獙鍒楄〃-鏁版嵁鏍煎紡娴嬭瘯(size)"""
        res = self.school.getQuiz(self.authorization, size=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_getQuiz_size(self, desc, value, code):
        """娴嬮獙鍒楄〃-杈圭晫鍊兼祴璇?size)"""
        res = self.school.getQuiz(self.authorization, size=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?

    def test_school_scenario_getQuiz_invalid_size(self):
        """娴嬮獙鍒楄〃-鍦烘櫙寮傚父-鏃犳晥鐨剆ize"""
        size = 999999999
        res = self.school.getQuiz(self.authorization, size=size)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    def test_school_positive_lesson_details3_ok(self):
        """鏇存柊璇惧爞淇℃伅-姝ｅ悜鐢ㄤ緥"""
        res = self.school.lesson_details3(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_lesson_details3(self, desc, value):
        """鏇存柊璇惧爞淇℃伅-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.lesson_details3(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_lesson_details3_lessonId(self, desc, value, code):
        """鏇存柊璇惧爞淇℃伅-蹇呭～瀛楁娴嬭瘯(lessonId)"""
        if desc == 'missing':
            pl = {'pop_items': 'lessonId'}
        else:
            pl = {'lessonId': value}
        res = self.school.lesson_details3(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_lesson_details3_lessonId(self, desc, value, code):
        """鏇存柊璇惧爞淇℃伅-鏁版嵁鏍煎紡娴嬭瘯(lessonId)"""
        res = self.school.lesson_details3(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_lesson_details3_lessonId(self, desc, value, code):
        """鏇存柊璇惧爞淇℃伅-杈圭晫鍊兼祴璇?lessonId)"""
        res = self.school.lesson_details3(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    def test_school_scenario_lesson_details3_invalid_lessonId(self):
        """鏇存柊璇惧爞淇℃伅-鍦烘櫙寮傚父-鏃犳晥鐨刲essonId"""
        lessonId = 999999999
        res = self.school.lesson_details3(self.authorization, lessonId=lessonId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_lesson_details3_req(self, desc, value, code):
        """鏇存柊璇惧爞淇℃伅-蹇呭～瀛楁娴嬭瘯(req)"""
        if desc == 'missing':
            pl = {'pop_items': 'req'}
        else:
            pl = {'req': value}
        res = self.school.lesson_details3(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_lesson_details3_req(self, desc, value, code):
        """鏇存柊璇惧爞淇℃伅-鏁版嵁鏍煎紡娴嬭瘯(req)"""
        res = self.school.lesson_details3(self.authorization, req=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_lesson_details3_req(self, desc, value, code):
        """鏇存柊璇惧爞淇℃伅-杈圭晫鍊兼祴璇?req)"""
        res = self.school.lesson_details3(self.authorization, req=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    def test_school_scenario_lesson_details3_invalid_req(self):
        """鏇存柊璇惧爞淇℃伅-鍦烘櫙寮傚父-鏃犳晥鐨剅eq"""
        req = 'INVALID_VALUE'
        res = self.school.lesson_details3(self.authorization, req=req)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
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
    def test_school_security_lesson_details3_req(self, desc, value):
        """鏇存柊璇惧爞淇℃伅-瀹夊叏娴嬭瘯(req)"""
        res = self.school.lesson_details3(self.authorization, req=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    def test_school_positive_lesson_details4_ok(self):
        """鍒犻櫎璇惧爞-姝ｅ悜鐢ㄤ緥"""
        res = self.school.lesson_details4(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_lesson_details4(self, desc, value):
        """鍒犻櫎璇惧爞-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.lesson_details4(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_lesson_details4_lessonId(self, desc, value, code):
        """鍒犻櫎璇惧爞-蹇呭～瀛楁娴嬭瘯(lessonId)"""
        if desc == 'missing':
            pl = {'pop_items': 'lessonId'}
        else:
            pl = {'lessonId': value}
        res = self.school.lesson_details4(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_lesson_details4_lessonId(self, desc, value, code):
        """鍒犻櫎璇惧爞-鏁版嵁鏍煎紡娴嬭瘯(lessonId)"""
        res = self.school.lesson_details4(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_lesson_details4_lessonId(self, desc, value, code):
        """鍒犻櫎璇惧爞-杈圭晫鍊兼祴璇?lessonId)"""
        res = self.school.lesson_details4(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    def test_school_scenario_lesson_details4_invalid_lessonId(self):
        """鍒犻櫎璇惧爞-鍦烘櫙寮傚父-鏃犳晥鐨刲essonId"""
        lessonId = 999999999
        res = self.school.lesson_details4(self.authorization, lessonId=lessonId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    def test_school_positive_groups1_ok(self):
        """鍒涘缓瀛︾敓鍒嗙粍-姝ｅ悜鐢ㄤ緥"""
        res = self.school.groups1(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_groups1(self, desc, value):
        """鍒涘缓瀛︾敓鍒嗙粍-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.groups1(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_groups1_lessonId(self, desc, value, code):
        """鍒涘缓瀛︾敓鍒嗙粍-蹇呭～瀛楁娴嬭瘯(lessonId)"""
        if desc == 'missing':
            pl = {'pop_items': 'lessonId'}
        else:
            pl = {'lessonId': value}
        res = self.school.groups1(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_groups1_lessonId(self, desc, value, code):
        """鍒涘缓瀛︾敓鍒嗙粍-鏁版嵁鏍煎紡娴嬭瘯(lessonId)"""
        res = self.school.groups1(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_groups1_lessonId(self, desc, value, code):
        """鍒涘缓瀛︾敓鍒嗙粍-杈圭晫鍊兼祴璇?lessonId)"""
        res = self.school.groups1(self.authorization, lessonId=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    def test_school_scenario_groups1_invalid_lessonId(self):
        """鍒涘缓瀛︾敓鍒嗙粍-鍦烘櫙寮傚父-鏃犳晥鐨刲essonId"""
        lessonId = 999999999
        res = self.school.groups1(self.authorization, lessonId=lessonId)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_groups1_req(self, desc, value, code):
        """鍒涘缓瀛︾敓鍒嗙粍-蹇呭～瀛楁娴嬭瘯(req)"""
        if desc == 'missing':
            pl = {'pop_items': 'req'}
        else:
            pl = {'req': value}
        res = self.school.groups1(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_groups1_req(self, desc, value, code):
        """鍒涘缓瀛︾敓鍒嗙粍-鏁版嵁鏍煎紡娴嬭瘯(req)"""
        res = self.school.groups1(self.authorization, req=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_groups1_req(self, desc, value, code):
        """鍒涘缓瀛︾敓鍒嗙粍-杈圭晫鍊兼祴璇?req)"""
        res = self.school.groups1(self.authorization, req=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    def test_school_scenario_groups1_invalid_req(self):
        """鍒涘缓瀛︾敓鍒嗙粍-鍦烘櫙寮傚父-鏃犳晥鐨剅eq"""
        req = 'INVALID_VALUE'
        res = self.school.groups1(self.authorization, req=req)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
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
    def test_school_security_groups1_req(self, desc, value):
        """鍒涘缓瀛︾敓鍒嗙粍-瀹夊叏娴嬭瘯(req)"""
        res = self.school.groups1(self.authorization, req=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    def test_school_positive_qrcode1_ok(self):
        """瀛︾敓鎵爜鐧诲綍-姝ｅ悜鐢ㄤ緥"""
        res = self.school.qrcode1(self.authorization)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_qrcode1(self, desc, value):
        """瀛︾敓鎵爜鐧诲綍-鏉冮檺娴嬭瘯"""
        # 閴存潈浣滀负浣嶇疆鍙傛暟鐩存帴浼犲叆锛堢ず渚嬫湡鏈涚殑鏋佺畝椋庢牸锛?
        res = self.school.qrcode1(value, code=401)
        if res:
            assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
            assert res['code'] == 401, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?01銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'unauthorized', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恥nauthorized銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_school_required_qrcode1_req(self, desc, value, code):
        """瀛︾敓鎵爜鐧诲綍-蹇呭～瀛楁娴嬭瘯(req)"""
        if desc == 'missing':
            pl = {'pop_items': 'req'}
        else:
            pl = {'req': value}
        res = self.school.qrcode1(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('string', 'abc', 500),
            ('float', 12.34, 200),
            ('boolean', True, 500),
            ('negative', -123, 200),
            ('array', [1, 2, 3], 500),
            ('object', {'key': 'value'}, 500),
            ('special_chars', '!@#$%^&*()', 500),
            ('emoji', '馃榾馃帀馃殌', 200),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500),
        ]
    )
    def test_school_format_qrcode1_req(self, desc, value, code):
        """瀛︾敓鎵爜鐧诲綍-鏁版嵁鏍煎紡娴嬭瘯(req)"""
        res = self.school.qrcode1(self.authorization, req=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 500),
            ('zero', 0, 500),
            ('max', 2147483647, 500),
        ]
    )
    def test_school_boundary_qrcode1_req(self, desc, value, code):
        """瀛︾敓鎵爜鐧诲綍-杈圭晫鍊兼祴璇?req)"""
        res = self.school.qrcode1(self.authorization, req=value, code=code)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == 'internal server error', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆?internal server error'銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
        else:
            assert res['code'] == '${pending}', f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['code']}銆?
            assert res['message'] == '${pending}', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恵'pending'}銆戯紝瀹為檯銆恵res['message']}銆?
            assert res['data'] == '${pending}', f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛氶鏈熴€恵'pending'}銆戯紝瀹為檯銆恵res['data']}銆?
    def test_school_scenario_qrcode1_invalid_req(self):
        """瀛︾敓鎵爜鐧诲綍-鍦烘櫙寮傚父-鏃犳晥鐨剅eq"""
        req = 'INVALID_VALUE'
        res = self.school.qrcode1(self.authorization, req=req)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"
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
    def test_school_security_qrcode1_req(self, desc, value):
        """瀛︾敓鎵爜鐧诲綍-瀹夊叏娴嬭瘯(req)"""
        res = self.school.qrcode1(self.authorization, req=value)
        assert isinstance(res, dict), f'鎺ュ彛杩斿洖绫诲瀷寮傚父: {type(res)}'
        assert res['code'] == 200, f"鎺ュ彛杩斿洖鐘舵€佺爜寮傚父: 棰勬湡銆?00銆戯紝瀹為檯銆恵res['code']}銆?
        assert res['message'] == 'success', f"鎺ュ彛杩斿洖message淇℃伅寮傚父: 棰勬湡銆恠uccess銆戯紝瀹為檯銆恵res['message']}銆?
        assert res['data'], f"鎺ュ彛杩斿洖data鏁版嵁寮傚父锛歿res['data']}"

