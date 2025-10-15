from time import strftime

import pytest
from pandas import DataFrame

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
        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.release
    def test_school_positive_putGroups_ok(self):
        """更新班级学生默认分组-正向用例"""
        className = '新增班级' + self.now
        class_id = self.school.school_class(self.authorization, className=className)['data']['id']
        students_res = self.school.batch(self.authorization, class_id)['data']
        studentIds = DataFrame(students_res).loc[:, "id"].tolist()
        res = self.school.putGroups(self.authorization, classId=class_id, groupSeqNo=0, studentIds=studentIds)
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
    def test_school_permission_putGroups(self, desc, value):
        """更新班级学生默认分组-权限测试"""
        res = self.school.putGroups(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', '123', 500, 500),    # todo
            ('float', 12.3, 500, 500),  # todo
            ('boolean', True, 500, 500),
            ('array', [1, 2, 3], 500, 500),
            ('object', {'key': 'value'}, 500, 500),
            ('special_chars', '!@#$%^&*()', 500, 500),
            ('email_format', 'test@example.com', 500, 500),
            ('phone_format', '13800138000', 500, 500),
            ('date_format', '2023-12-25', 500, 500),
            ('emoji', '😀🎉🚀', '', '')
        ]
    )
    def test_school_permission_putGroups_groupSeqNo(self, desc, value, code, code_res):
        """获取当前正在进行的扭蛋活动-数据格式测试(language)"""
        try:
            className = '新增班级' + self.now
            class_id = self.school.school_class(self.authorization, className=className)['data']['id']
            students_res = self.school.batch(self.authorization, class_id)['data']
            studentIds = DataFrame(students_res).loc[:, "id"].tolist()
            res = self.school.putGroups(self.authorization, classId=class_id, groupSeqNo=value, studentIds=studentIds, code=code)
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
        'desc, value, code, code_res',
        [
            ('string', '123', 500, 500),
            ('float', 12.3, 500, 500),
            ('boolean', True, 500, 500),
            ('array', [1, 2, 3], 200, 200), # todo
            ('empty_array', [], 200, 200),  # todo
            ('object', {'key': 'value'}, 500, 500),
            ('special_chars', '!@#$%^&*()', 500, 500),
            ('email_format', 'test@example.com', 500, 500),
            ('phone_format', '13800138000', 500, 500),
            ('date_format', '2023-12-25', 500, 500),
            ('emoji', '😀🎉🚀', '', ''),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500, 500),
            ('unicode', '中文测试', '', ''),
            ('json_string', '{"key": "value"}', 500, 500),
            ('xml_string', '<root><item>test</item></root>', 500, 500),
            ('url_string', 'https://www.example.com', 500, 500),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 500, 500),
        ]
    )
    def test_school_permission_putGroups_studentIds(self, desc, value, code, code_res):
        """获取当前正在进行的扭蛋活动-数据格式测试(studentIds)"""
        try:
            class_id = self.school.school_class(self.authorization)['data']['id']
            res = self.school.putGroups(self.authorization, classId=class_id, groupSeqNo=1, studentIds=value, code=code)
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
    def test_school_positive_getNormalcourse_ok(self):
        """Normal课程资源列表-正向用例"""
        res = self.school.getNormalcourse(self.authorization)
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
    def test_school_permission_getNormalcourse(self, desc, value):
        """Normal课程资源列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.school.getNormalcourse(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('int', 123, 500, 500),    # todo
            ('float', 12.3, 500, 500),  # todo
            ('boolean', True, 500, 500),
            ('array', [1, 2, 3], 500, 500),
            ('object', {'key': 'value'}, 500, 500),
            ('special_chars', '!@#$%^&*()', 500, 500),
            ('email_format', 'test@example.com', 500, 500),
            ('phone_format', '13800138000', 500, 500),
            ('date_format', '2023-12-25', 500, 500),
            ('emoji', '😀🎉🚀', '', ''),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 500, 500),
            ('unicode', '中文测试', '', ''),
            ('json_string', '{"key": "value"}', 500, 500),
            ('xml_string', '<root><item>test</item></root>', 500, 500),
            ('url_string', 'https://www.example.com', 500, 500),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 500, 500),
        ]
    )
    def test_school_format_getNormalcourse_keyword(self, desc, value, code, code_res):
        """Normal课程资源列表-数据格式测试(keyword)"""
        try:
            res = self.school.getNormalcourse(self.authorization, keyword=value, code=code)
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