import json
from time import strftime

import pytest
from pandas import DataFrame

from test_case.page_api.admin.admin_quiz_api import AdminQuizApi
from test_case.page_api.admin.admin_school_api import AdminSchoolApi
from test_case.page_api.book.book_api import BookApi
from test_case.page_api.school.school_api import SchoolApi
from config import RunConfig
from test_case.page_api.user.user_api import UserApi

base_url = RunConfig.baseurl
expired_token = RunConfig.expired_token

class TestSchoolApi:
    """school 接口测试用例"""

    def setup_class(self):
        self.admin_school = AdminSchoolApi()
        self.book = BookApi()
        self.user = UserApi()
        self.admin = AdminQuizApi()
        self.school = SchoolApi()
        self.authorization, self.userId = self.school.get_authorization()
        self.auth_admin, self.userId_a = self.admin_school.get_admin_authorization()
        self.now = strftime("%Y%m%d%H%M%S")

    def teardown_class(self):
        '''删除测试班级'''
        class_res = self.admin_school.admin_class_list(self.auth_admin, self.userId_a, all=True)
        for _class in class_res['data']['content']:
            if _class['className'].startswith('dibo_test'):
                class_id = _class['id']
                # 删除班级
                self.admin_school.delete_admin_class(self.auth_admin, class_id, self.userId_a)

    @pytest.fixture(scope='function')
    def create_class(self):
        '''创建班级数据'''
        class_list = self.admin_school.admin_class_list(self.auth_admin, self.userId_a)['data']['content']
        for _class in class_list:
            # 删除班级
            class_id = _class['id']
            students = self.admin_school.class_students(self.auth_admin, class_id, self.userId_a)['data']['content']
            for student in students:
                student_id = student['id']
                delete_res = self.admin_school.delete_student(self.auth_admin, student_id, self.userId_a)
                assert delete_res['code'] == 200
            self.admin_school.delete_admin_class(self.auth_admin, class_id, self.userId_a)
        # 创建班级
        pl = {
            "className": "baidi_test" + self.now,
            "imageUrl": "",
            "room": "101",
            "subject": "History",
            "teacherUserId": self.userId_a
        }
        class_id = self.admin_school.admin_create_class(self.auth_admin, self.userId_a, **pl)['data']['id']

        yield class_id

        # 删除班级
        self.admin_school.delete_admin_class(self.auth_admin, class_id, self.userId_a)

    @pytest.fixture(scope='function')
    def school_fixture(self):
        '''创建班级数据'''
        pl = {
            "className": "debbie_test_a" + self.now,
            "imageUrl": "",
            "room": "101",
            "subject": "History",
            "teacherUserId": self.userId_a
        }
        class_a_id = self.admin_school.admin_create_class(self.auth_admin, self.userId_a, **pl)['data']['id']
        # 批量添加学生
        student_names = ['class_a1', 'class_a2']
        pl1 = {"studentNames": student_names}
        students_res = self.admin_school.batch_add_student(self.auth_admin, class_a_id, self.userId_a, **pl1)['data']
        studentIds_a = DataFrame(students_res).loc[:, "id"].tolist()

        # 创建班级
        pl = {
            "className": "debbie_test_b" + self.now,
            "imageUrl": "",
            "room": "101",
            "subject": "History",
            "teacherUserId": self.userId_a
        }
        class_b_id = self.admin_school.admin_create_class(self.auth_admin, self.userId_a, **pl)['data']['id']
        student_names = ['class_b1', 'class_b2']
        # 批量添加学生
        pl1 = {"studentNames": student_names}
        students_res = self.admin_school.batch_add_student(self.auth_admin, class_b_id, self.userId_a, **pl1)['data']
        studentIds_b = DataFrame(students_res).loc[:, "id"].tolist()

        # 创建班级
        pl = {
            "className": "debbie_test_c" + self.now,
            "imageUrl": "",
            "room": "101",
            "subject": "History",
            "teacherUserId": self.userId_a
        }
        class_c_id = self.admin_school.admin_create_class(self.auth_admin, self.userId_a, **pl)['data']['id']
        student_names = ['class_c1', 'class_c2']
        # 批量添加学生
        pl1 = {"studentNames": student_names}
        students_res = self.admin_school.batch_add_student(self.auth_admin, class_c_id, self.userId_a, **pl1)['data']
        studentIds_c = DataFrame(students_res).loc[:, "id"].tolist()

        yield [(class_a_id, studentIds_a), (class_b_id, studentIds_b), (class_c_id, studentIds_c)]

        for class_id in [class_a_id, class_b_id, class_c_id]:
            # 删除班级
            self.admin_school.delete_admin_class(self.auth_admin, class_id, self.userId_a)
            
    @pytest.mark.release
    def test_admin_school_positive_admin_create_class(self):
        '''admin班级 - 增删改查验证'''
        class_list = self.admin_school.admin_class_list(self.auth_admin, self.userId_a)['data']['content']
        for _class in class_list:
            # 删除班级
            class_id = _class['id']
            students = self.admin_school.class_students(self.auth_admin, class_id, self.userId_a)['data']['content']
            for student in students:
                student_id = student['id']
                delete_res = self.admin_school.delete_student(self.auth_admin, student_id, self.userId_a)
                assert delete_res['code'] == 200
            self.admin_school.delete_admin_class(self.auth_admin, class_id, self.userId_a)
        # 创建班级
        className = "baidi_test" + self.now
        pl = {
            "className": className,
            "imageUrl": "",
            "room": "101",
            "subject": "History",
            "teacherUserId": self.userId_a
        }
        class_id = self.admin_school.admin_create_class(self.auth_admin, self.userId_a, **pl)['data']['id']
        # 创建班级后，获取班级列表，验证添加成功
        add_list = self.admin_school.admin_class_list(self.auth_admin, self.userId_a)['data']
        for _class in add_list['content']:
            if _class['className'] == className:
                assert  _class['className'] == className
                assert  _class['imageUrl'] == pl.get('imageUrl')
                assert  _class['room'] == pl.get('room')
                assert  _class['subject'] == pl.get('subject')
                break
        else:
            assert False, "新增班级后，未在返回的班级列表中找到新增得班级！"

        # 更新班级信息
        classNameNew = "baidi_test_new" + self.now
        update_pl = {
            "className": classNameNew,
            "imageUrl": "https://baidu.com",
            "room": "102",
            "subject": "English",
            "teacherUserId": self.userId_a
        }
        update_res = self.admin_school.update_admin_class(self.auth_admin, class_id, self.userId_a, **update_pl)
        assert update_res['message'] == "success"
        # 更新班级信息后，获取班级列表，验证更新成功
        update_list = self.admin_school.admin_class_list(self.auth_admin, self.userId_a)['data']
        for _class in update_list['content']:
            if _class['id'] == class_id:
                assert  _class['className'] == classNameNew
                assert  _class['imageUrl'] == update_pl.get('imageUrl')
                assert  _class['room'] == update_pl.get('room')
                assert  _class['subject'] == update_pl.get('subject')
                break
        else:
            assert False, "新增班级后，未在返回的班级列表中找到新增得班级！"

        # 删除班级
        self.admin_school.delete_admin_class(self.auth_admin, class_id, self.userId_a)
        # 删除班级后，获取班级列表，验证删除班级成功
        delete_list = self.admin_school.admin_class_list(self.auth_admin, self.userId_a)['data']['content']
        if delete_list:
            class_ids = DataFrame(delete_list).loc[:, "id"].tolist()
            assert class_id not in class_ids

    @pytest.mark.release
    def test_admin_school_class_student_check(self, create_class):
        '''admin班级学生 - 增删改查验证'''
        # 创建班级
        class_id = create_class

        # 批量添加学生
        student_names = ['student_1', 'student_2', 'student_3', 'student_4', 'student_5', 'student_6']
        pl = {"studentNames": student_names}
        # students_res = self.admin_school.batch_add_student(self.auth_admin, class_id, self.userId_a, **pl)['data']
        students_res = self.school.batch(self.authorization, class_id, **pl)['data']
        studentIds = DataFrame(students_res).loc[:, "id"].tolist()
        # 创建班级后，获取班级列表，验证添加成功
        add_list = self.admin_school.class_students(self.auth_admin, class_id, self.userId_a)['data']['content']
        for student in add_list:
            assert student['studentName'] in student_names
        assert len(studentIds) == len(add_list)
        student_id = studentIds[0]

        pl = {
            "avatarUrl": "https://creator.qakjukl.net/swagger-ui.html#/admin-school-controller/batchAddStudentsUsingPOST",
            "studentName": "student_1_newname",
            "username": "qqq"
        }
        update_res = self.admin_school.update_student(self.auth_admin, student_id, self.userId_a, **pl)
        assert update_res['message'] == "success"
        # 更新班级信息后，获取班级列表，验证更新成功
        update_list = self.admin_school.class_students(self.auth_admin, class_id, self.userId_a)['data']['content']
        for student in update_list:
            if student['id'] == student_id:
                assert student['studentName'] == pl.get('studentName')
                assert student['username'] == pl.get('username')
                assert student['avatarUrl'] == pl.get('avatarUrl')
                break
        else:
            assert False, "新增班级后，未在返回的班级列表中找到新增得班级！"

        # 删除班级
        self.admin_school.delete_student(self.auth_admin, class_id, self.userId_a)
        # 删除班级后，获取班级列表，验证删除班级成功
        delete_list = self.admin_school.class_students(self.auth_admin, class_id, self.userId_a)['data']['content']
        if delete_list:
            class_ids = DataFrame(delete_list).loc[:, "id"].tolist()
            assert class_id not in class_ids
        
    @pytest.mark.release
    def test_admin_school_positive_migrate_ok(self, school_fixture):
        """迁移学生-正向用例"""
        # 迁移学生前获取classa classb classc班级中的学生
        [(class_a_id, studentIds_a), (class_b_id, studentIds_b), (class_c_id, studentIds_c)] = school_fixture
        for class_info in school_fixture:
            class_students_res = self.admin_school.class_students(self.auth_admin, class_info[0])
            res_ids = DataFrame(class_students_res["data"]["content"]).loc[:, "id"].tolist()
            assert res_ids == class_info[1]

        # 将classb与classc中的学生迁移到classa
        res = self.admin_school.migrate_student(self.auth_admin, [class_b_id, class_c_id], class_a_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

        # 验证学生迁移成功
        students_a = self.admin_school.class_students(self.auth_admin, class_a_id)
        students_a_res = DataFrame(students_a["data"]["content"]).loc[:, "id"].tolist()
        assert students_a_res == studentIds_a + studentIds_b + studentIds_c
        students_b = self.admin_school.class_students(self.auth_admin, class_b_id)
        assert not students_b['data']["content"]
        students_c = self.admin_school.class_students(self.auth_admin, class_c_id)
        assert not students_c['data']["content"]

    @pytest.mark.release
    def test_admin_school_positive_getLessons_all_ok(self, create_class):
        """获取班级课堂列表-正向用例"""
        # 获取全局class_id
        class_id = create_class
        # 批量添加学生
        student_names = ['student_1', 'student_2', 'student_3', 'student_4', 'student_5', 'student_6']
        pl = {"studentNames": student_names}
        students_res = self.admin_school.batch_add_student(self.auth_admin, class_id, self.userId_a, **pl)['data']
        studentIds = DataFrame(students_res).loc[:, "id"].tolist()

        lesson_id = self.admin_school.create_lesson(self.auth_admin, class_id, self.userId_a)['data']['id']
        lessonName = "baidi_test_lesson" + self.now
        pl = {
            "lessonName": lessonName,
            "resources": [
                {
                    "id": 0,
                    "resourceType": "type1"
                }
            ],
            "teachingLanguage": "zh",
            "voiceRecognition": True
        }
        add_list = self.admin_school.class_lessons(self.auth_admin, class_id, self.userId_a)
        for lesson in add_list:
            if lesson['lessonName'] == lessonName:
                assert  studentIds['resources'] == pl.get('resources')
                assert  studentIds['teachingLanguage'] == pl.get('teachingLanguage')
                assert  studentIds['voiceRecognition'] == pl.get('voiceRecognition')
                break
        else:
            assert False, "新增班级后，未在返回的班级列表中找到新增得班级！"

        lessonNameNew = "baidi_test_lesson_new" + self.now
        update_pl = {
            "lessonName": lessonNameNew,
            "resources": [
                {
                    "id": 0,
                    "resourceType": "type2"
                }
            ],
            "teachingLanguage": "en",
            "voiceRecognition": False
        }
        update_res = self.admin_school.update_lesson(self.auth_admin, lesson_id, class_id, self.userId_a, **update_pl)
        assert update_res['message'] == "success"
        # 更新班级信息后，获取班级列表，验证更新成功
        update_list = self.admin_school.class_lessons(self.auth_admin, class_id, self.userId_a)
        for lesson in update_list:
            if lesson['id'] == lesson_id:
                assert  studentIds['lessonName'] == lessonNameNew
                assert  studentIds['resources'] == pl.get('resources')
                assert  studentIds['teachingLanguage'] == pl.get('teachingLanguage')
                assert  studentIds['voiceRecognition'] == pl.get('voiceRecognition')
                break
        else:
            assert False, "新增班级后，未在返回的班级列表中找到新增得班级！"

        self.admin_school.delete_lesson(self.auth_admin, lesson_id, self.userId_a)
        # 删除班级后，获取班级列表，验证删除班级成功
        delete_list = self.admin_school.class_lessons(self.auth_admin, class_id, self.userId_a)
        if delete_list:
            class_ids = DataFrame(delete_list).loc[:, "id"].tolist()
            assert class_id not in class_ids

    @pytest.mark.release
    def test_admin_school_positive_admin_create_class1(self):
        """admin后台班级-增删改查验证"""
        # 创建班级
        className = 'dibo_test_class' + self.now
        class_id = self.admin_school.admin_create_class(self.auth_admin, self.userId_a, className=className, teacherUserId=self.userId_a)['data']['id']
        # 批量添加学生
        students_res = self.admin_school.batch_add_student(self.auth_admin, class_id, self.userId_a)['data']
        studentIds = DataFrame(students_res).loc[:, "id"].tolist()
        # 更新班级学生默认分组
        res = self.admin_school.update_students_class_groups(self.auth_admin, class_id, self.userId_a, groupSeqNo=0, studentIds=studentIds)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"