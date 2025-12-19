import json
from time import strftime

import pytest
from pandas import DataFrame

from test_case.page_api.admin.admin_quiz_api import AdminQuizApi
from test_case.page_api.book.book_api import BookApi
from test_case.page_api.school.school_api import SchoolApi
from config import RunConfig
from test_case.page_api.user.user_api import UserApi

base_url = RunConfig.baseurl
expired_token = RunConfig.expired_token

class TestSchoolApi:
    """school 接口测试用例"""

    def setup_class(self):
        self.school = SchoolApi()
        self.book = BookApi()
        self.user = UserApi()
        self.admin = AdminQuizApi()
        self.authorization, self.userId = self.school.get_authorization()
        self.now = strftime("%Y%m%d%H%M%S")


    def teardown_class(self):
        '''删除测试班级'''
        class_res = self.school.class_list(self.authorization, all=True)
        for _class in class_res['data']['content']:
            if _class['className'].startswith('dibo_test'):
                class_id = _class['id']
                # 删除班级
                self.school.delete_class(self.authorization, class_id)

    @pytest.fixture(scope='class')
    def create_class(self):
        '''创建班级数据'''
        # 创建班级
        pl = {
            "className": "baidi_test" + self.now,
            "description": "三年级历史学习班",
            "grade": 5,
            "subject": "History"
        }
        class_id = self.school.school_class(self.authorization, **pl)['data']['id']
        student_names = ['student_1', 'student_2', 'student_3', 'student_4', 'student_5', 'student_6']
        # 批量添加学生
        pl = {"studentNames": student_names}
        students_res = self.school.batch(self.authorization, class_id, **pl)['data']
        studentIds = DataFrame(students_res).loc[:, "id"].tolist()

        yield class_id, studentIds

        # 删除班级
        self.school.delete_class(self.authorization, class_id)
        
    @pytest.fixture(scope='function')
    def create_lesson_function(self):
        # 创建班级
        class_id = self.school.school_class(self.authorization)['data']['id']
        student_names = ['student1', 'student2', 'student3', 'student4', 'student5', 'student6']
        # 批量添加学生
        pl = {"studentNames": student_names}
        self.school.batch(self.authorization, class_id, **pl)['data']
        # 创建课堂
        lessonId = self.school.create_lesson(self.authorization, classId=class_id)['data']['id']
        yield lessonId
        # 删除班级
        self.school.delete_class(self.authorization, class_id)
        
    @pytest.fixture(scope='class')
    def create_lesson(self):
        '''创建课程'''
        # 创建班级
        class_id = self.school.school_class(self.authorization)['data']['id']
        # Normal课程资源列表
        course_id = self.school.getNormalcourse(self.authorization)["data"]['content'][0]['id']
        resources = [
            {
                "resourceType": "course",
                "id": course_id
            }
        ]
        # 创建课堂
        lesson_id = self.school.lesson(self.authorization, classId=class_id, resources=resources)['data']['id']
        # 获取课堂学习资源
        resource_id = self.school.lesson_resources(self.authorization, lessonId=lesson_id)['data'][0]['resourceId']
        # 批量添加学生
        students_id = self.school.batch(self.authorization, class_id)['data'][0]['id']
        # 获取quiz列表
        res_quiz = self.admin.quiz_list(self.authorization)['data']['content'][0]
        quizId, quizData = res_quiz['id'], res_quiz['quizData']

        yield class_id, lesson_id, resource_id, students_id, quizId, quizData


    @pytest.fixture(scope='function')
    def school_fixture(self):
        '''创建班级数据'''
        pl = {
            "className": "debbie_test_a" + self.now,
            "description": "三年级数学学习班",
            "grade": 3,
            "subject": "Math"
        }
        class_a_id = self.school.school_class(self.authorization, **pl)['data']['id']
        # 批量添加学生
        student_names = ['class_a1', 'class_a2']
        pl1 = {"studentNames": student_names}
        students_res = self.school.batch(self.authorization, class_a_id, **pl1)['data']
        studentIds_a = DataFrame(students_res).loc[:, "id"].tolist()

        # 创建班级
        pl = {
            "className": "debbie_test_b" + self.now,
            "description": "三年级数学学习班",
            "grade": 3,
            "subject": "Math"
        }
        class_b_id = self.school.school_class(self.authorization, **pl)['data']['id']
        student_names = ['class_b1', 'class_b2']
        # 批量添加学生
        pl1 = {"studentNames": student_names}
        students_res = self.school.batch(self.authorization, class_b_id, **pl1)['data']
        studentIds_b = DataFrame(students_res).loc[:, "id"].tolist()

        # 创建班级
        pl = {
            "className": "debbie_test_c" + self.now,
            "description": "三年级数学学习班",
            "grade": 3,
            "subject": "Math"
        }
        class_c_id = self.school.school_class(self.authorization, **pl)['data']['id']
        student_names = ['class_c1', 'class_c2']
        # 批量添加学生
        pl1 = {"studentNames": student_names}
        students_res = self.school.batch(self.authorization, class_c_id, **pl1)['data']
        studentIds_c = DataFrame(students_res).loc[:, "id"].tolist()

        yield [(class_a_id, studentIds_a), (class_b_id, studentIds_b), (class_c_id, studentIds_c)]

        for class_id in [class_a_id, class_b_id, class_c_id]:
            # 删除班级
            self.school.delete_class(self.authorization, class_id)

    @pytest.mark.smoke
    def test_school_positive_putGroups_ok(self):
        """更新班级学生默认分组-正向用例"""
        # 创建班级
        className = 'dibo_test_class' + self.now
        class_id = self.school.school_class(self.authorization, className=className)['data']['id']
        # 批量添加学生
        students_res = self.school.batch(self.authorization, class_id)['data']
        studentIds = DataFrame(students_res).loc[:, "id"].tolist()
        # 更新班级学生默认分组
        res = self.school.putGroups(self.authorization, classId=class_id, groupSeqNo=0, studentIds=studentIds)
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
    def test_school_permission_putGroups(self, desc, value):
        """更新班级学生默认分组-权限测试"""
        res = self.school.putGroups(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

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

    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', '123', 500, 500),
            ('float', 12.3, 500, 500),
            ('boolean', True, 500, 500),
            ('array', [1, 2, 3], 200, 200),
            ('empty_array', [], 200, 200),
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

    @pytest.mark.smoke
    def test_school_positive_getNormalcourse_ok(self):
        """Normal课程资源列表-正向用例"""
        res = self.school.getNormalcourse(self.authorization)
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
    def test_school_permission_getNormalcourse(self, desc, value):
        """Normal课程资源列表-权限测试"""
        
        res = self.school.getNormalcourse(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('int', 123, 500, 500),    # todo
            ('float', 12.3, 500, 500),  # todo
            ('boolean', True, 500, 500), # todo
            ('array', [1, 2, 3], 500, 500), # todo
            ('object', {'key': 'value'}, 500, 500), # todo
            ('special_chars', '!@#$%^&*()', 200, 200),
            ('email_format', 'test@example.com', 200, 200),
            ('phone_format', '13800138000', 200, 200),
            ('date_format', '2023-12-25', 200, 200),
            ('emoji', '😀🎉🚀', '', ''),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 200, 200),
            ('unicode', '中文测试', '', ''),
            ('json_string', '{"key": "value"}', 200, 200),
            ('xml_string', '<root><item>test</item></root>', 200, 200),
            ('url_string', 'https://www.example.com', 200, 200),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 200),
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

    @pytest.mark.smoke
    def test_school_positive_getQuiz_ok(self):
        """测验列表-正向用例"""
        res = self.school.getQuiz(self.authorization)
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
    def test_school_permission_getQuiz(self, desc, value):
        """测验列表-权限测试"""
        res = self.school.getQuiz(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('int', 123, 500, 500),    # todo
            ('float', 12.3, 500, 500),  # todo
            ('boolean', True, 500, 500), # todo
            ('array', [1, 2, 3], 500, 500), # todo
            ('object', {'key': 'value'}, 500, 500), # todo
            ('special_chars', '!@#$%^&*()', 403, ''),
            ('email_format', 'test@example.com', 403, ''),
            ('phone_format', '13800138000', 200, 200),
            ('date_format', '2023-12-25', 200, 200),
            ('emoji', '😀🎉🚀', '', ''),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 200, 200),
            ('unicode', '中文测试', '', ''),
            ('json_string', '{"key": "value"}', 200, 200),
            ('xml_string', '<root><item>test</item></root>', 200, 200),
            ('url_string', 'https://www.example.com', 403, ''),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 200),
        ]
    )
    def test_school_format_getQuiz_keyword(self, desc, value, code, code_res):
        """测验列表-数据格式测试(keyword)"""
        try:
            res = self.school.getQuiz(self.authorization, keyword=value, code=code)
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

    @pytest.mark.smoke
    def test_school_positive_getList1_ok(self):
        """测验报告列表-正向用例"""
        # 创建班级
        class_id = self.school.school_class(self.authorization)
        lessonId = self.school.create_lesson(self.authorization, classId=class_id)['data']['id']
        res = self.school.school_quiz_reports(self.authorization, lessonId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert 'data' in res.keys(), f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_getList1(self, desc, value):
        """测验报告列表-权限测试"""
        
        res = self.school.getList1(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 400, 100006),
            ('float', 12.34, 400, 100006),
            ('boolean', True, 400, 100006),
            ('negative', -123, 400, 100006),    # todo
            ('array', [1, 2, 3], 400, 100006),
            ('object', {'key': 'value'}, 400, 100006),
            ('special_chars', '!@#$%^&*()', 400, 100006),
            ('emoji', 'test_emoji', 400, 100006),
        ]
    )
    def test_school_format_getList1_lessonId(self, desc, value, code, code_res):
        """测验报告列表-数据格式测试(lessonId)"""
        try:
            res = self.school.getList1(self.authorization, lessonId=value, code=code)
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
        elif code_res == 100006:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【100006】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.smoke
    def test_school_positive_create_groups_ok(self, create_lesson_function):
        """测验报告列表-正向用例"""
        lessonId = create_lesson_function
        res = self.school.create_groups(self.authorization, lessonId, groupCount=3)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert 'data' in res.keys(), f"接口返回data数据异常：{res['data']}"

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
        """创建学生分组-权限测试"""
        
        res = self.school.create_groups(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
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
    def test_school_permission_putGroups1(self, desc, value):
        """更新课堂学生默认分组-权限测试"""
        
        res = self.school.update_groups(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_quiz_report_ok(self, create_lesson):
        """测验报告详情-正向用例"""
        class_id, lesson_id, resource_id, students_id, quizId, quizData = create_lesson
        res_quiz = self.admin.quiz_list(self.authorization)['data']['content'][0]
        quizId, quizData = res_quiz['id'], json.loads(res_quiz['quizData'])
        pl = {
            "studentId": students_id,
            "resourceId": resource_id,
            "answers": [
                {
                    "instructionalDomain": "认知",
                    "questionSeqNo": 1,
                    "questionType": "single-choice",
                    "score": 2,
                    "answerData": "{\"selectedId\": \"umbrella\", \"selectedAnswer\": \"Umbrella\"}",
                    "answerTime": "2025-02-01T10:00:00",
                    "duration": 30
                },
                {
                    "instructionalDomain": "认知",
                    "questionSeqNo": 2,
                    "questionType": "single-choice",
                    "score": 2,
                    "answerData": "{\"selectedId\": \"umbrella\", \"selectedAnswer\": \"Umbrella\"}",
                    "answerTime": "2025-02-01T10:00:00",
                    "duration": 30
                },
                {
                    "instructionalDomain": "认知",
                    "questionSeqNo": 3,
                    "questionType": "single-choice",
                    "score": 2,
                    "answerData": "{\"selectedId\": \"umbrella\", \"selectedAnswer\": \"Umbrella\"}",
                    "answerTime": "2025-02-01T10:00:00",
                    "duration": 30
                },
                {
                    "instructionalDomain": "认知",
                    "questionSeqNo": 4,
                    "questionType": "single-choice",
                    "score": 2,
                    "answerData": "{\"selectedId\": \"umbrella\", \"selectedAnswer\": \"Umbrella\"}",
                    "answerTime": "2025-02-01T10:00:00",
                    "duration": 30
                },
                {
                    "instructionalDomain": "认知",
                    "questionSeqNo": 5,
                    "questionType": "single-choice",
                    "score": 2,
                    "answerData": "{\"selectedId\": \"umbrella\", \"selectedAnswer\": \"Umbrella\"}",
                    "answerTime": "2025-02-01T10:00:00",
                    "duration": 30
                },
            ]
        }
        self.school.report(self.authorization, lessonId=lesson_id, quizId=quizId, **pl)
        lessonReportId = self.school.school_quiz_reports(self.authorization, lesson_id)['data'][0]['id']
        res = self.school.quiz_report(self.authorization, lesson_id, lessonReportId)
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
    def test_school_permission_quiz_report(self, desc, value):
        """测验报告详情-权限测试"""
        res = self.school.quiz_report(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_migrate_ok(self, school_fixture):
        """迁移学生-正向用例"""
        # 迁移学生前获取classa classb classc班级中的学生
        [(class_a_id, studentIds_a), (class_b_id, studentIds_b), (class_c_id, studentIds_c)] = school_fixture
        for class_info in school_fixture:
            class_students_res = self.school.getStudents(self.authorization, class_info[0])
            res_ids = DataFrame(class_students_res["data"]["content"]).loc[:, "id"].tolist()
            assert res_ids == class_info[1]

        # 将classb与classc中的学生迁移到classa
        res = self.school.migrate(self.authorization, [class_b_id, class_c_id], class_a_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

        # 验证学生迁移成功
        students_a = self.school.getStudents(self.authorization, class_a_id)
        students_a_res = DataFrame(students_a["data"]["content"]).loc[:, "id"].tolist()
        assert students_a_res == studentIds_a + studentIds_b + studentIds_c
        students_b = self.school.getStudents(self.authorization, class_b_id)
        assert not students_b['data']["content"]
        students_c = self.school.getStudents(self.authorization, class_c_id)
        assert not students_c['data']["content"]

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_migrate(self, desc, value):
        """迁移学生-权限测试"""
        
        res = self.school.migrate(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_class_group_qrcode_ok(self, create_class):
        """获取班级小组二维码-正向用例"""
        # 创建班级数据
        class_id, studentIds = create_class
        # 获取班级小组二维码
        res = self.school.class_group_qrcode(self.authorization, class_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['qrCodeContent'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_class_group_qrcode(self, desc, value):
        """获取班级小组二维码-权限测试"""
        
        res = self.school.class_group_qrcode(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_scenario_class_group_qrcode_invalid_groupSeqNo(self, create_class):
        """获取班级小组二维码-场景异常-无效的groupSeqNo"""
        groupSeqNo = 999999999
        class_id, studentIds = create_class
        res = self.school.class_group_qrcode(self.authorization, class_id, groupSeqNo=groupSeqNo)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100136, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'This group not found', f"接口返回message信息异常: 预期【This group not found】，实际【{res['message']}】"
        assert res['data'] == 'This group not found', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_getLessons_page_ok(self, create_class):
        """获取班级课堂列表-正向用例"""
        # 获取全局class_id
        class_id, studentIds = create_class
        # 在班级中创建课程
        pl = {'lessonName': 'debbie_lesson_test'}
        lessonId = self.school.create_lesson(self.authorization, classId=class_id, **pl)['data']['id']
        try:
            res = self.school.getLessons(self.authorization, class_id)
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert lessonId in DataFrame(res['data']['content'])['id'].tolist(), f"接口返回data数据异常：{res['data']}"
        finally:
            self.school.delete_lesson(self.authorization, lessonId)

    @pytest.mark.smoke
    def test_school_positive_getLessons_all_ok(self, create_class):
        """获取班级课堂列表-正向用例"""
        # 获取全局class_id
        class_id, studentIds = create_class
        # 在班级中创建101堂课程-验证如果all=true 返回全部数据，最多100条
        lessonIds = []
        for i in range(101):
            lessonId = self.school.create_lesson(self.authorization, classId=class_id)['data']['id']
            lessonIds.append(lessonId)
        try:
            res = self.school.getLessons(self.authorization, class_id, all=True)
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert len(res['data']['content']) == 100, f"接口返回data数据异常：{res['data']}"
            assert res['data']['pageable']['pageSize'] == 100, f"接口返回data数据异常：{res['data']}"
        finally:
            for lessonId in lessonIds:
                self.school.delete_lesson(self.authorization, lessonId)

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
        """获取班级课堂列表-权限测试"""
        
        res = self.school.getLessons(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_favorite_course_ok(self):
        """收藏资源 - 资源为课程 - 正向用例"""
        resourceRefId = self.school.getNormalcourse(self.authorization)["data"]['content'][0]['id']
        pl = {
            "resourceRefId": resourceRefId,
            "resourceType": "COURSE"
        }
        try:
            res = self.school.favorite(self.authorization, **pl)
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data']['resourceId'] == str(resourceRefId)
            assert res['data']['resourceType'] == 'course'
            assert res['data']['userId'] == self.userId
        finally:
            res = self.school.deleteFavorite(self.authorization, **pl)
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"

    @pytest.mark.smoke
    def test_school_positive_favorite_quiz_ok(self):
        """收藏资源 - 资源为quiz - 正向用例"""
        resourceRefId = self.school.getQuiz(self.authorization)["data"]['content'][0]['id']
        pl = {
            "resourceRefId": resourceRefId,
            "resourceType": "QUIZ"
        }
        try:
            res = self.school.favorite(self.authorization, **pl)
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data']['resourceId'] == str(resourceRefId)
            assert res['data']['resourceType'] == 'quiz'
            assert res['data']['userId'] == self.userId
        finally:
            res = self.school.deleteFavorite(self.authorization, **pl)
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"

    @pytest.mark.smoke
    def test_school_positive_favorite_repeat_check(self):
        """收藏资源-验证同一资源不能重复收藏"""
        # Normal课程资源列表
        resourceRefId = self.school.getNormalcourse(self.authorization)["data"]['content'][1]['id']
        pl = {
            "resourceRefId": resourceRefId,
            "resourceType": "COURSE"
        }
        try:
            # 如果已经收藏过了，则再次收藏会报错；如果没有收藏过，制造第一次收藏验证不能重复收藏
            self.school.favorite(self.authorization, **pl)
        except:
            pass
        # 重复收藏资源
        res = self.school.favorite(self.authorization, code=500, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 500, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【internal server error】，实际【{res['message']}】"
        assert res['data']

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_favorite(self, desc, value):
        """收藏资源-权限测试"""
        res = self.school.favorite(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_deleteFavorite_course_ok(self):
        """取消收藏资源-课程-正向用例"""
        try:
            # Normal课程资源列表
            resourceRefId = self.school.getNormalcourse(self.authorization)["data"]['content'][0]['id']
            pl = {
                "resourceRefId": resourceRefId,
                "resourceType": "COURSE"
            }
            # 收藏资源
            res = self.school.favorite(self.authorization, **pl)
        except:
            pass
        # 取消收藏资源
        res = self.school.deleteFavorite(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == True, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_deleteFavorite_quiz_ok(self):
        """取消收藏资源"""
        try:
            # 测验列表
            resourceRefId = self.school.getQuiz(self.authorization)["data"]['content'][0]['id']
            pl = {
                "resourceRefId": resourceRefId,
                "resourceType": "QUIZ"
            }
            # 收藏资源
            res = self.school.favorite(self.authorization, **pl)
        except:
            pass
        # 取消收藏资源
        res = self.school.deleteFavorite(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == True, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_deleteFavorite_false_check(self):
        """取消收藏资源-检测资源未被收藏资源取消"""
        # Normal课程资源列表
        resourceRefId = self.school.getNormalcourse(self.authorization)["data"]['content'][0]['id']
        pl = {
            "resourceRefId": resourceRefId,
            "resourceType": "COURSE"
        }
        # 取消收藏资源
        res = self.school.deleteFavorite(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == False, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_deleteFavorite(self, desc, value):
        """取消收藏资源-权限测试"""
        res = self.school.deleteFavorite(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_report_ok(self):
        """测验结果上报"""
        # 获取用户的班级列表
        class_res = self.school.class_list(self.authorization, size=100)['data']['content']
        for class_info in class_res:
            class_id = class_info['id']
            lesson_res = self.school.getLessons(self.authorization, class_id)['data']['content']
            if lesson_res:
                lesson_id = lesson_res[0]['id']
                lesson_name = lesson_res[0]['lessonName']
                break
        else:
            assert False, "未找到有课程的班级!"
        # 测验列表
        quiz_id = self.school.getQuiz(self.authorization)['data']['content'][0]['id']
        resources = [
            { "resourceType": "quiz", "id": quiz_id}
        ]
        # 更新课堂信息
        update_res = self.school.update_lesson(self.authorization, lesson_id, lesson_name, class_id, resources)
        assert update_res['code'] == 200, "更新课堂信息失败！"
        # 获取班级学生列表
        students_res = self.school.getStudents(self.authorization, class_id)['data']['content']
        if not students_res:
            student_names = ['baidi', 'huangmin']
            pl = {"studentNames": student_names}
            self.school.batch(self.authorization, class_id, **pl)
            students_res = self.school.getStudents(self.authorization, class_id)['data']['content']
        students_id = students_res[0]['id']
        # 测验结果上报
        answers = []
        for i in range(10):
            answers.append({
                  "instructionalDomain": "认知维度",
                  "questionSeqNo": i+1,
                  "questionType": "选择题",
                  "score": 10,
                  "answerData": "{\"selected\":\"A\"}",
                  "answerTime": "2024-01-15T10:30:00",
                  "duration": 30
            })
        pl = {
            "studentId": students_id,
            "answers": answers
        }
        res = self.school.report(self.authorization, lessonId=lesson_id, quizId=quiz_id, **pl)
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == True, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_report(self, desc, value):
        """测验结果上报-权限测试"""
        
        res = self.school.report(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_quiz_reports_ok(self):
        """测验报告列表-正向用例"""
        # 获取用户的班级列表
        class_res = self.school.class_list(self.authorization, size=100)['data']['content']
        for class_info in class_res:
            class_id = class_info['id']
            lesson_res = self.school.getLessons(self.authorization, class_id)['data']['content']
            if lesson_res:
                lesson_id = lesson_res[0]['id']
                lesson_name = lesson_res[0]['lessonName']
                break
        else:
            assert False, "未找到有课程的班级!"

        # 测验列表
        quiz_id = self.school.getQuiz(self.authorization)['data']['content'][0]['id']
        resources = [
            { "resourceType": "quiz", "id": quiz_id}
        ]
        # 更新课堂信息
        update_res = self.school.update_lesson(self.authorization, lesson_id, lesson_name, class_id, resources)
        assert update_res['code'] == 200, "更新课堂信息失败！"
        # 获取班级学生列表
        students_res = self.school.getStudents(self.authorization, class_id)['data']['content']
        if not students_res:    # 如果没有学生，则创建
            student_names = ['baidi', 'huangmin',]
            pl = {"studentNames": student_names}
            self.school.batch(self.authorization, class_id, **pl)
            students_res = self.school.getStudents(self.authorization, class_id)['data']['content']
        students_id = students_res[0]['id']
        answers = []
        for i in range(10):
            answers.append({
                  "instructionalDomain": "认知维度",
                  "questionSeqNo": i+1,
                  "questionType": "选择题",
                  "score": 10,
                  "answerData": "{\"selected\":\"A\"}",
                  "answerTime": "2024-01-15T10:30:00",
                  "duration": 30
            })
        pl = {
            "studentId": students_id,
            "answers": answers
        }
        # 测验结果上报
        res = self.school.report(self.authorization, lessonId=lesson_id, quizId=quiz_id, **pl)
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == True, f"接口返回data数据异常：{res['data']}"
        # 测验报告列表
        res_reports = self.school.school_quiz_reports(self.authorization, lesson_id)
        assert isinstance(res_reports, dict), f'接口返回类型异常: {type(res_reports)}'
        assert res_reports['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res_reports['code']}】"
        assert res_reports['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res_reports['message']}】"
        assert res_reports['data'][0]['lessonId'] == lesson_id
        assert res_reports['data'][0]['lessonResourceId'] == quiz_id
        assert res_reports['data'][0]['name'].startswith('quiz_report')

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_quiz_reports(self, desc, value):
        """测验报告列表-权限测试"""
        
        res = self.school.school_quiz_reports(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_lesson_skills_ok(self):
        """课程技能标签列表-正向用例"""
        res = self.school.lesson_skills(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_lesson_skills(self, desc, value):
        """课程技能标签列表-权限测试"""
        res = self.school.lesson_skills(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_skill_themes_ok(self):
        """技能主题列表（按技能分组展示课程）-正向用例"""
        res = self.school.skill_themes(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_skill_themes(self, desc, value):
        """技能主题列表（按技能分组展示课程）-权限测试"""
        
        res = self.school.skill_themes(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_getStorybookThemes_ok(self):
        """故事书主题列表（按标签分组展示故事书）-正向用例"""
        res = self.school.getStorybookThemes(self.authorization)
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
    def test_school_permission_getStorybookThemes(self, desc, value):
        """故事书主题列表（按标签分组展示故事书）-权限测试"""
        
        res = self.school.getStorybookThemes(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_lessonStorybook_ok(self):
        """故事书资源列表-正向用例"""
        tagId = self.school.getStorybookThemes(self.authorization)['data'][0]['id']
        res = self.school.lessonStorybook(self.authorization, tagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_school_permission_lessonStorybook(self, desc, value):
        """故事书资源列表-权限测试"""
        res = self.school.lessonStorybook(value, 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_getNormalcourse_onlyFavorite_ok(self):
        """Normal课程资源列表-正向用例"""
        pl = {
            "skillId": None,
            "onlyFavorite": True
        }
        res = self.school.getNormalcourse(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['content'][0]['name'] == 'Sea Animals', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_getNormalcourse_notOnlyFavorite_ok(self):
        """Normal课程资源列表-正向用例"""
        skillId = self.school.lesson_skills(self.authorization)['data'][0]['id']
        pl = {
            "skillId": skillId,
            "onlyFavorite": False
        }
        res = self.school.getNormalcourse(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_school_positive_storybookThemes_ok(self):
        """故事书主题列表（按标签分组展示故事书）-正向用例"""
        res = self.school.storybookThemes(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    @pytest.mark.parametrize('onlyFavorite', [True, False])
    def test_school_lessonStorybook_onlyFavorite_ok(self, onlyFavorite):
        """故事书资源列表-正向用例"""
        # 故事书主题列表（按标签分组展示故事书）
        themes_res = self.school.storybookThemes(self.authorization)['data']
        for theme in themes_res:
            tagId = theme['id']
            pl = {
                "onlyFavorite": onlyFavorite,
            }
            books_res = self.school.lessonStorybook(self.authorization, tagId=tagId, **pl)['data']['content']
            for book in books_res:
                assert book['isFavorite'] == onlyFavorite

    @pytest.mark.smoke
    def test_school_lessonStorybook_official_ok(self):
        """故事书资源列表-正向用例"""
        # 故事书主题列表（按标签分组展示故事书）
        themes_res = self.school.storybookThemes(self.authorization)['data']
        for theme in themes_res:
            tagId = theme['id']
            pl = {"official": 1}
            books_res = self.school.lessonStorybook(self.authorization, tagId=tagId, **pl)['data']['content']
            for book in books_res:
                # 通过bookId查询书籍详情，获取作者名称
                authorName = book['authorName']
                # 根据用户名搜索用户获取用户email
                user_email_res = self.user.getSearch(self.authorization, authorName)['data']['content']
                for user_email in user_email_res:
                    email = user_email['email']
                    if email.endswith('@giggleacademy.com') or email.endswith('@giggleacademy.me'):
                        break
                else:
                    assert False, "预期筛选社区故事书，但是结果不满足！"

    @pytest.mark.smoke
    def test_school_lessonStorybook_selected_ok(self):
        """故事书资源列表-正向用例"""
        # 根据书名 / 作者名 / 标签搜索书籍
        data_res0 = []
        for _type in ['PUBLIC', 'FAVORITE', 'MINE']:
            data_res = self.book.searchBook(self.authorization, type=_type)['data']['content']
            data_res0 = data_res0 + data_res
        data_df = DataFrame(data_res0, columns=["id", "selected"])
        # 故事书主题列表（按标签分组展示故事书）
        themes_res = self.school.storybookThemes(self.authorization)['data']
        for theme in themes_res:
            # 故事书资源列表
            tagId = theme['id']
            pl = {"selected": 1}
            books_res = self.school.lessonStorybook(self.authorization, tagId=tagId, **pl)['data']['content']
            for book in books_res:
                # 通过bookId查询书籍详情，获取作者名称
                bookId = book['id']
                selected_actual = data_df[data_df["id"] == str(bookId)]["selected"].iloc[0]
                assert int(selected_actual) == 1