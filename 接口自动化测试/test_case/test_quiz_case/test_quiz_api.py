import pytest

from test_case.page_api.admin.admin_course_api import AdminCourseApi
from test_case.page_api.admin.admin_quiz_api import AdminQuizApi
from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.curriculum.curriculum_api import CurriculumApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.quiz.quiz_api import QuizApi
from config import RunConfig

base_url = RunConfig.baseurl
expired_token = RunConfig.expired_token

class TestQuizApi:
    """
    quiz 接口测试用例
    """

    def setup_class(self):
        self.quiz = QuizApi()
        self.kid = KidApi()
        self.course = CourseApi()
        self.admin = AdminQuizApi()
        self.curriculum = CurriculumApi()
        self.admin_course = AdminCourseApi()
        self.authorization = self.quiz.get_authorization()[0]
        self.admin_auth = self.admin_course.get_admin_authorization()[0]

    @pytest.fixture(scope="class")
    def getkidId(self):
        '''类前置 - 获取kidId'''
        kid_res = self.kid.getKids(self.authorization)
        yield kid_res['data'][0]['id']

    @pytest.mark.smoke
    def test_quiz_positive_quizId_detail_ok(self):
        """查询指定quiz的详情"""
        # 获取quiz列表
        res_quiz = self.admin.quiz_list(self.authorization)['data']['content'][0]
        quizId, quizData = res_quiz['id'], res_quiz['quizData']
        # 查询指定quiz的详情
        res = self.quiz.quizId_detail(self.authorization, quizId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_quiz_positive_promotion_submit_ok(self, kid_data_session):
        """提交晋级Quiz（批量提交并完成）-正向用例"""
        # 创建测试学生
        kid_id = kid_data_session[0]
        pl = {"kidId": kid_id}
        # 提交晋级Quiz（批量提交并完成）
        res = self.quiz.promotion_submit(self.authorization, **pl)
        assert res['message'] == 'success'
        promotion_data = {
            "newLevel": "L2",
            "previousLevel": "L1",
            "promotionSuccess": True,
            "targetLevelAccuracy": 1.0
        }
        assert res['data'] == promotion_data, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_quiz_permission_promotion_submit(self, desc, value):
        """submitPromotionQuiz-权限测试"""
        res = self.quiz.promotion_submit(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_quiz_positive_submit_lesson_quiz_ok(self, getkidId):
        """提交课后quiz-正向用例"""
        kidId = getkidId
        courseId = 1
        pl = {
            "kidId": kidId,
            "courseId": courseId,
            "completeTimeStamp": 0,
            "questions": [
                {
                    "quizId": "string",
                    "questionId": 0,
                    "questionSeqNo": 0,
                    "question": "string",
                    "userAnswer": "string",
                    "correctAnswer": "string",
                    "isCorrect": True,
                    "skillTags": [
                        "string"
                    ],
                "completeTimeStamp": 0
                }
            ]
        }
        res = self.quiz.submit_lesson_quiz(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert not res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_quiz_permission_submit_lesson_quiz(self, desc, value):
        """提交课后quiz-权限测试"""
        res = self.quiz.submit_lesson_quiz(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_course_positive_quiz_promotion(self, kid_data_session):
        '''学生升级 - 升级quiz - 晋级流程测试'''
        # 创建测试学生
        kid_id = kid_data_session
        # 查询晋级资格
        pl = {
            "quizType": "PROMOTION",
            "kidId": kid_id,
            "count": 12
        }
        # 根据题库获取Quiz题目
        questions_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data']
        assert questions_res['level'] == currentLevel
        quizId = questions_res['quizId']
        questions = questions_res['questions']


        # 获取顶层课程目录列表
        topcategory_res = self.admin_course.getAlltopcategory(self.admin_auth)
        for category in topcategory_res['data']:
            parentId = category['id']
            # 获取课程子目录列表
            category_res1 = self.admin_course.getAllsubcategory(self.admin_auth, parentId)
            for subcategory in category_res1['data']:
                parentId1 = subcategory['id']
                # 获取课程子目录列表
                category_res2 = self.admin_course.getAllsubcategory(self.admin_auth, parentId1)
                for subcategory2 in category_res2['data']:
                    categoryId = subcategory2['id']
                    # 获取分类下所有课程
                    courselistAll = self.admin_course.course_listAll(self.admin_auth, categoryId)
                    for course in courselistAll['data']:
                        course_difficulty = course['difficulty']
                        course_id = course['id']
                        course_name = course['name']
                        skills = course['skillList']
                        # 题库列表查询（分页）
                        course_quiz_res = self.admin_quiz.quiz_questions(self.authorization, courseName=course_name)

        level_contents = self.curriculum.curriculum_level_contents(self.authorization, level_id, kid_id)['data'][0]
        part_len = len(level_contents['parts'])
        print(part_len)