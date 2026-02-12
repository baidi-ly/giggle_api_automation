import pytest
from pandas import DataFrame

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
        kid_id = kid_data_session[0]
        # 步骤1: 获取课程路径
        curriculum_paths = self.curriculum.get_curriculum_by_country(self.authorization, countryCode='JP')
        assert curriculum_paths["code"] == 200, f"获取课程路径失败: {curriculum_paths}"
        assert curriculum_paths["data"], "没有找到课程路径"

        # 选择第一个路径
        path_id = curriculum_paths["data"]["id"]
        # 步骤2: 获取该路径下的所有学习等级
        levels = self.curriculum.get_level_list(self.authorization, path_id)['data']
        for level in levels:
            if level['levelName'] == 'Level 1':
                level_id = level['id']
        level_contents = self.curriculum.curriculum_level_contents(self.authorization, level_id, kid_id)['data']
        course_ids = {}
        for i in level_contents:
            for part in i['parts']:
                for content in part['contents']:
                    _ = []
                    if content['resourceType'] == 'COURSE':
                        if not content['config']['gameSteps']:
                            _.append('')
                        else:
                            _.append(content['id'])
                    if _:
                        if content['resourceId'] in course_ids:
                            for _id in _:
                                course_ids[content['resourceId']].append(_id)
                        else:
                            course_ids[content['resourceId']] = _

        # 查询晋级资格
        pl = {
            "quizType": "PROMOTION",
            "kidId": kid_id,
            "count": 12,
            'levelId': level_id
        }
        # 根据题库获取Quiz题目
        questions_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]
        quizId = questions_res['quizId']
        questions = questions_res['questions']
        print('quizId:', quizId)
        for question in questions:
            flag = False
            question_id = question['id']
            print('question_id:', question_id)
            # 获取顶层课程目录列表
            topcategory_res = self.admin_course.getAlltopcategory(self.admin_auth)
            for category in topcategory_res['data']:
                parentId = category['id']
                print('parentId:', parentId)
                # 获取课程子目录列表
                category_res1 = self.admin_course.getAllsubcategory(self.admin_auth, parentId)
                for subcategory in category_res1['data']:
                    parentId1 = subcategory['id']
                    print('parentId1:', parentId1)
                    category_res1 = self.admin_course.getAllsubcategory(self.admin_auth, parentId1)
                    for subcategory in category_res1['data']:
                        parentId1 = subcategory['id']
                        print('parentId1:', parentId1)
                        # 获取分类下所有课程
                        courselistAll = self.admin_course.course_listAll(self.admin_auth, parentId1)
                        for course in courselistAll['data']:
                            quizIds = []
                            quizIds1 = []
                            course_name = course['name']
                            print('course_name:', course_name)
                            course_id = course['id']
                            if course_id == '648882465919047':
                                pass

                            # 题库列表查询（分页）
                            course_quiz_res = self.admin.quiz_questions(self.authorization, courseName=course_name)['data']['content']

                            if course_quiz_res:
                                comps_df = DataFrame(course_quiz_res)
                                quizIds = comps_df[comps_df["courseId"] == course_id]['id'].tolist()
                                if not quizIds:
                                    quizIds = comps_df[comps_df["courseId"] == int(course_id)]['id'].tolist()
                                print(quizIds)

                                if question_id in quizIds:
                                    print('course_id>>>>>>>>>>>>>>>>>>>>>>>', course_id)
                                    print('question_id>>>>>>>>>>>>>>>>>>>>>>>', question_id)
                                    for content_id in course_ids[course_id]:
                                        if content_id:
                                            assert course_id in course_ids
                                            curriculumContentId = comps_df[comps_df["id"] == question_id]['curriculumContentId'].tolist()[0]
                                            if curriculumContentId:
                                                assert int(curriculumContentId) in course_ids[course_id]
                                        else:
                                            assert course_id in course_ids
                                    flag = True
                                    break

                    if flag:
                        break
                if flag:
                    break
            if not flag:
                print('zuihoyibu:-------------', question_id)
                assert False


    def test_course_positive_quiz_promotion(self, kid_data_session):
        '''学生升级 - 升级quiz - 晋级流程测试'''

        # 创建测试学生
        kid_id = kid_data_session[0]
        # 步骤1: 获取课程路径
        curriculum_paths = self.curriculum.get_curriculum_by_country(self.authorization, countryCode='JP')
        assert curriculum_paths["code"] == 200, f"获取课程路径失败: {curriculum_paths}"
        assert curriculum_paths["data"], "没有找到课程路径"

        # 选择第一个路径
        path_id = curriculum_paths["data"]["id"]
        # 步骤2: 获取该路径下的所有学习等级
        levels = self.curriculum.get_level_list(self.authorization, path_id)['data']
        for level in levels:
            if level['levelName'] == 'Level 1':
                level_id = level['id']
        level_contents = self.curriculum.curriculum_level_contents(self.authorization, level_id, kid_id)['data']
        course_ids = {}
        for i in level_contents:
            for part in i['parts']:
                for content in part['contents']:
                    if content['resourceType'] == 'COURSE':
                        course_name = content['resourceName']
                        course_id = content['resourceId']
                        if not content['config']['gameSteps']:
                            pl = {
                                "count": 36,
                                "kidId": kid_id,
                                "quizType": "LESSON",
                                "courseId": course_id
                            }
                            question_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]
                            questions = question_res['questions']
                            for question in questions:
                                question_id = question['id']

                                # 题库列表查询（分页）
                                course_quiz_res = \
                                self.admin.quiz_questions(self.authorization, courseName=course_name)['data']['content']

                                if course_quiz_res:
                                    comps_df = DataFrame(course_quiz_res)
                                    quizIds = comps_df[comps_df["courseId"] == course_id]['id'].tolist()
                                    if not quizIds:
                                        quizIds = comps_df[comps_df["courseId"] == int(course_id)]['id'].tolist()
                                    print(quizIds)
                                    assert question_id in quizIds
                        else:
                            curriculumContentId = content['id']
                            pl = {
                                "count": 36,
                                "kidId": kid_id,
                                "quizType": "LESSON",
                                "curriculumContentId": curriculumContentId,
                                "courseId": course_id
                            }
                            question_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]
                            questions = question_res['questions']
                            for question in questions:
                                question_id = question['id']
                                # 题库列表查询（分页）
                                course_quiz_res = self.admin.quiz_questions(self.authorization, courseName=course_name)['data']['content']

                                if course_quiz_res:
                                    comps_df = DataFrame(course_quiz_res)
                                    quizIds = comps_df[comps_df["courseId"] == course_id]['id'].tolist()
                                    if not quizIds:
                                        quizIds = comps_df[comps_df["courseId"] == int(course_id)]['id'].tolist()
                                    print(quizIds)

                                    assert question_id in quizIds
                                    curriculumContentIds = comps_df[comps_df["id"] == question_id]['curriculumContentId'].tolist()
                                    if curriculumContentIds != [None]:
                                        assert int(curriculumContentId) == int(curriculumContentIds[0])


