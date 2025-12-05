import datetime
import json
import random
import string
import time
from time import strftime

import pytest
import sys
import os

from pandas import DataFrame

import config
from test_case.page_api.admin.admin_course_api import AdminCourseApi
from test_case.page_api.admin.admin_kid_api import AdminKidApi
from test_case.page_api.admin.admin_levelskills_api import AdminLevelskillsApi
from test_case.page_api.admin.admin_quiz_api import AdminQuizApi
from test_case.page_api.aiserver.aiserver_api import AiServerApi
from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.quiz.quiz_api import QuizApi
from test_case.page_api.school.school_api import SchoolApi
from test_case.page_api.user.user_api import UserApi

sys.path.append(os.getcwd())
sys.path.append("..")

expired_token = config.RunConfig.expired_token

@pytest.mark.Course
class TestCourse:

    def setup_class(self):
        self.course = CourseApi()
        self.school = SchoolApi()
        self.kid = KidApi()
        self.user = UserApi()
        self.quiz = QuizApi()
        self.ai_server = AiServerApi()
        self.admin_course = AdminCourseApi()
        self.admin_level = AdminLevelskillsApi()
        self.admin_kid = AdminKidApi()
        self.admin_quiz = AdminQuizApi()
        self.now = strftime("%Y%m%d%H%M%S")
        self.authorization, self.userId = self.course.get_authorization()
        # self.authorization_admin = self.admin_course.get_admin_authorization()[0]

        kids_res = self.kid.getKids(self.authorization)
        for kid in kids_res['data']:
            if kid['name'] == 'giggle-kid-UHS4NE':
                self.kid_id = kid['id']
                break

        # # 批量新增等级技能
        # self.skillIds = []
        # for i in range(3):
        #     educationType = "dibo_test" + self.now + str(i)
        #     pl = {
        #         "educationType": educationType,
        #     }
        #     skill_id = self.admin_level.createLevelSkill(self.authorization, **pl)['data']['id']
        #     self.skillIds.append(skill_id)

    def setup_method(self):
        '''获取kid_id'''
        self.kid_id = self.kid.getKids(self.authorization)["data"][0]['id']

    def teardown_class(self):
        '''清除所有课程用户标签测试数据'''
        try:
            for status in [0, 1]:
                pl = {"status": status}
                course_tags = self.admin_course.course_tag_list(self.authorization, **pl)['data']
                for course_tag in course_tags:
                    # 删除课程用户标签
                    if course_tag['name'].startswith('course_tag_test'):
                        course_tag_id = course_tag['id']
                        delete_res = self.admin_course.delete_course_tag(self.authorization, course_tag_id)
                        assert delete_res['data'] == '删除成功', f"接口返回data数据异常：{delete_res['data']}"
        except Exception as e:
            print(f'删除课程用户标签失败，原因是：{e}')

        try:
            questions_res = self.admin_quiz.quiz_questions(self.authorization, 'Colors', size=1000)
            questionIds = DataFrame(questions_res['data']['content'])['id'].tolist()
            for questionId in questionIds:
                # 删除quiz题目
                self.admin_quiz.delete_quiz_question(self.authorization, questionId)
        except Exception as e:
            print(f'删除quiz题目失败，原因是：{e}')

        try:
            for status in [0, 1]:
                pl = {"status": status}
                course_tags = self.admin_course.course_tag_list(self.authorization, **pl)['data']['content']
                for course_tag in course_tags:
                    # 删除课程用户标签
                    if course_tag['name'].startswith('course_tag_test'):
                        course_tag_id = course_tag['id']
                        if status == 1:
                            tag_id = course_tag['id']
                            pl = {
                                "name": course_tag['name'],
                                "multilingualKey": course_tag['multilingualKey'],
                                "skillIds": course_tag['skills'],
                                "status": 0
                            }
                            self.admin_course.update_course_tag(self.authorization, tag_id, **pl)
                        delete_res = self.admin_course.delete_course_tag(self.authorization, course_tag_id)
                        assert delete_res['data'] == '删除成功', f"接口返回data数据异常：{delete_res['data']}"
        except Exception as e:
            print(f'删除课程用户标签失败，原因是：{e}')

        try:
            # 获取所有教育类型为dibo_test开头的等级技能
            delete_skills = []
            level_skills = self.admin_level.level_skills(self.authorization)['data']
            for course_skill in level_skills:
                if course_skill['educationType'].startswith('dibo_test'):
                    delete_skills.append(course_skill['id'])
            # 删除等级技能
            if delete_skills:
                del_res = self.admin_level.deleteLevelskills(self.authorization, delete_skills)
                assert del_res['code'] == 200
        except Exception as e:
            print(f'删除等级技能失败，原因是：{e}')

    @pytest.fixture(scope='function')
    def createCourseTag_method(self):
        '''方法固件 - 创建课程用户标签'''
        # 创建课程用户标签
        tag_name = 'course_tag_test' + self.now + random.choice(string.ascii_letters)
        pl = {
            "name": tag_name,
            "multilingualKey": "tag.reading",
            "tagType": 'normal', # 必填，可选值包括 normal、hot、recommended_search 等。
            "status": 1,
            "skillIds": self.skillIds, # 关联的课程等级技能 ID 列表，Long 数组，可选，默认空数组。
        }

        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + f'/test_data/story_face.webp', 'rb'))
        }
        res = self.admin_course.create_course_tag(self.authorization, file=file, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        course_tag_id = res['data']['id']

        yield course_tag_id

        # 删除课程标签
        res = self.admin_course.delete_course_tag(self.authorization, course_tag_id)
        assert res['code'] == 200, f"删除课程标签失败！"

    def test_course_blockedCourseIds_login(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        stats_res = self.course.blockedCourseIds(self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["blockedIds"]

    def test_course_blockedCourseIds_customer(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        stats_res = self.course.blockedCourseIds('')
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["blockedIds"]

    @pytest.mark.smoke
    def test_course_positive_recommendation_ok(self):
        """获取课程推荐-正向用例"""
        course_id = self.school.getNormalcourse(self.authorization)["data"]['content'][0]['id']
        kid_id = self.kid.getKids(self.authorization)["data"][0]['id']
        pl = {
            "currentCourseId": course_id,
            "includeReasonInfo": False,
            "kidId": kid_id,
            "recommendCount": 2
        }
        res = self.course.recommendation(self.authorization, **pl)
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
    def test_course_permission_recommendation(self, desc, value):
        """获取课程推荐-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.course.recommendation(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_course_positive_getTags_ok(self):
        """查询所有推荐和热门标签-正向用例"""
        res = self.course.getTags(self.authorization)
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
    def test_course_permission_getTags(self, desc, value):
        """查询所有推荐和热门标签-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.course.getTags(value)
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.fixture(scope='function')
    def create_course_tag_method(self):
        # 创建多个等级技能
        skillIds = []
        for i in range(3):
            educationType = "debbie_test" + self.now + str(i)
            pl = {
                "educationType": educationType,
            }
            skill_id = self.admin_course.createLevelSkill(self.authorization, **pl)['data']['id']
            skillIds.append(skill_id)
        # 创建课程用户标签
        tag_name = 'course_tag_test' + self.now
        pl = {
            "name": tag_name,
            "multilingualKey": "tag.reading",
            "tagType": 'normal', # 必填，可选值包括 normal、hot、recommended_search 等。
            "status": 1,
            "skillIds": skillIds, # 关联的课程等级技能 ID 列表，Long 数组，可选，默认空数组。
        }

        file = {
            'coverImage': ('story_face.webp', open(os.getcwd() + f'/test_data/story_face.webp', 'rb'))
        }
        create_res = self.admin_course.create_course_tag(self.authorization, file=file, **pl)
        course_tag_id = create_res['data']['id']    # 用户标签ID

        yield course_tag_id

        # 删除课程用户标签
        res = self.admin_course.delete_course_tag(self.authorization, course_tag_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"

        # 删除等级技能
        del_res = self.admin_course.deleteLevelskills(self.authorization, skillIds)
        assert del_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{del_res['code']}】"

    @pytest.mark.smoke
    def test_course_positive_getAlbums_ok(self):
        """查询所有生效中的专辑及其标签-正向用例"""
        '''
        /course/tag/create
        POST /course/album/create
        '''
        res = self.course.course_albums(self.authorization)
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
    def test_course_permission_getAlbums(self, desc, value):
        """查询所有生效中的专辑及其标签-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.course.course_albums(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_course_positive_promotion_check_ok(self):
        """查询晋级资格-正向用例"""
        res = self.course.promotion_check(self.authorization, self.kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert ('eligible' and 'currentLevel' and 'targetLevel' and 'masteredSkillCount'
                and 'totalNecessarySkillCount') in res['data']

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_course_permission_promotion_check(self, desc, value):
        """查询晋级资格-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.course.promotion_check(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    @pytest.mark.parametrize('learningLevel', [
        'L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L8', 'L9', 'L10',
        'L11', 'L12', 'L13', 'L14', 'L15', 'L16','L17', 'L18', 'L19', 'L20'
    ])
    def test_course_positive_course_recommends_ok(self, learningLevel):
        """获取课程推荐列表（需要认证）-正向用例"""
        res = self.course.course_recommends(self.authorization, self.kid_id, learningLevel)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        course_recommends = res['data']
        if course_recommends:
            for course in course_recommends:
                assert course['difficulty'] == learningLevel

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
    def test_course_permission_course_recommends(self, desc, value):
        """获取课程推荐列表（需要认证）-权限测试"""
        res = self.course.course_recommends(value, 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    @pytest.mark.parametrize('learningLevel', [
        'L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L8', 'L9', 'L10',
        'L11', 'L12', 'L13', 'L14', 'L15', 'L16','L17', 'L18', 'L19', 'L20'
    ])
    def test_course_positive_course_public_recommends_ok(self, learningLevel):
        """获取课程推荐列表（公开接口）-正向用例"""
        res = self.course.course_public_recommends(self.authorization, learningLevel)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        course_public_recommends = res['data']
        if course_public_recommends:
            for course in course_public_recommends:
                assert course['difficulty'] == learningLevel

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
    def test_course_permission_course_public_recommends(self, desc, value):
        """获取课程推荐列表（公开接口）-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.course.course_public_recommends(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        course_public_recommends = res['data']
        for course in course_public_recommends:
            assert course['difficulty'] == 'L1'

    @pytest.mark.smoke
    @pytest.mark.parametrize('learningLevel', [
        'L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L8', 'L9', 'L10',
        'L11', 'L12', 'L13', 'L14', 'L15', 'L16','L17', 'L18', 'L19', 'L20'
    ])
    def test_course_positive_getTagBaseRecommend_ok(self, learningLevel):
        """获取推荐课程列表-正向用例"""
        res = self.course.getTagBaseRecommend(self.authorization, self.kid_id, learningLevel)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        tagBaseRecommends = res['data']['content']
        if tagBaseRecommends:
            for course in tagBaseRecommends:
                assert course['difficulty'] == learningLevel

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
    def test_course_permission_getTagBaseRecommend(self, desc, value):
        """获取推荐课程列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.course.getTagBaseRecommend(value, self.kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        tagBaseRecommends = res['data']['content']
        for course in tagBaseRecommends:
            assert course['difficulty'] == 'L1'

    @pytest.mark.smoke
    def test_course_positive_coursesByTag_ok(self, createCourseTag_method):
        """根据标签ID查询对应的课程列表-正向用例"""
        tagId = createCourseTag_method
        res = self.course.coursesByTag(self.authorization, tagId)
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
    def test_course_permission_coursesByTag(self, desc, value, createCourseTag_method):
        """根据标签ID查询对应的课程列表-权限测试"""
        tagId = createCourseTag_method
        res = self.course.coursesByTag(value, tagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.fixture(scope="class")
    def getSecondekidId(self):
        '''类前置 - 获取kidId'''
        kid_res = self.kid.getKids(self.authorization)['data']
        for kid in kid_res:
            if kid['name'] == "uuid":
                kid_id = kid['id']
                break
        yield kid_id

    def test_course_positive_questionnaire(self, getSecondekidId):
        '''
        未问卷-公共推荐
        '''

    def test_course_positive_quiz_placement(self):
        '''问卷调查-定级-'''
        '''
        定级流程测试：
        /kid/placement/check?kidId={kidId}
        /quiz/fetch-questions
            正常获取定级题目（默认12题）
            验证题目不重复（已使用题目ID过滤）
            验证题目覆盖不同技能和组件
        /quiz/placement/submit
        /kid/placement/check?kidId={kidId}
        /user/kid/{kidId}/learning-level
        /admin/kid/{kidId}/interaction-preference
        /admin/kid/{kidId}/skill-mastery
        /game/course/tag-base-recommend
        '''
        # kid_id = getSecondekidId
        kid_id = 715049880240197
        # check_res1 = self.kid.check_placement(self.authorization, kid_id)
        # assert check_res1['data']['currentLevel'] == 'L1'
        # assert check_res1['data']['needPlacement'] == True
        # assert check_res1['data']['initialLevel'] == 'L1'
        # assert check_res1['data']['levelRange'] == {'max': 'L5', 'min': 'L1'}
        placementLevel = 'L1'
        levelList = [placementLevel]
        pl = {
            "count": 12,
            "kidId": kid_id,
            "levelList": levelList
        }
        question_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]
        assert question_res['level'] == 'L1'
        quizId = question_res['quizId']
        questions = question_res['questions']
        assert len(questions) == 12
        answers = []
        for question in questions:
            assert question['difficulty'] == 'L1'
            questionContent = json.loads(question['questionContent'])
            if 'answers' in questionContent:
                userAnswer = questionContent['answers']
                correctAnswer = questionContent['answers']
            elif 'answer' in questionContent:
                userAnswer = questionContent['answer']
                correctAnswer = questionContent['answer']
            else:
                userAnswer = ''
                correctAnswer = ''
            answers.append(
                {
                    "quizId": quizId,
                    "questionId": question['id'],
                    "questionSeqNo": questions.index(question),
                    "question": questionContent['question'],
                    "userAnswer": userAnswer,
                    "correctAnswer": correctAnswer,
                    "isCorrect": True,
                    "skillTags": [
                        question['skill']
                    ],
                    "completeTimeStamp": 0
                }
            )
        placement_res = self.quiz.placementSubmit(self.authorization, kid_id, placementLevel, answers)
        # assert placement_res['message'] == 'success'

        check_res2 = self.kid.check_placement(self.authorization, kid_id)
        assert check_res2['data']['currentLevel'] == 'L1'
        assert check_res2['data']['needPlacement'] == True
        assert check_res2['data']['initialLevel'] == 'L1'
        assert check_res2['data']['levelRange'] == {'max': 'L5', 'min': 'L1'}

        learninglevel_res = self.user.getLearningLevel(self.authorization, kid_id)
        assert learninglevel_res['data']['learningLevel'] == 'L1'
        tags_res = self.admin_kid.getKidTags(self.authorization, kid_id)
        assert tags_res['data']['childAge'] == 6
        assert tags_res['data']['kidId'] == str(kid_id)
        assert tags_res['data']['learningLevel'] == 'L1'
        lp_res = self.kid.getLearningProgress(self.authorization, kid_id)
        # assert lp_res['data']['childAge'] == 6
        assert lp_res['data']['kidId'] == kid_id
        assert lp_res['data']['learningLevel'] == 'L1'
        assert lp_res['data']['valueOld']
        assert lp_res['data']['valueNew']
        assert lp_res['data']['masteryPercent']
        ip_res = self.admin_kid.getInteractionPreference(self.authorization, kid_id)
        assert ip_res['data']['kidId'] == str(kid_id)
        assert ip_res['data']['preferences'] == []
        sm_res = self.admin_kid.getSkillMastery(self.authorization, kid_id)
        assert sm_res['data']['kidId'] == str(kid_id)
        assert sm_res['data']['skillMasteryMap']
        recommends_res = self.course.course_recommends(self.authorization, kid_id, placementLevel)['data']
        for course in recommends_res:
            assert course['difficulty'] == 'L1'

    def test_course_positive_quiz_lesson(self, getSecondekidId):
        '''问卷调查-定级-'''
        '''
        课后quiz测试：
        /kid/placement/check?kidId={kidId}
        /quiz/fetch-questions
            正常获取定级题目（默认12题）
            验证题目不重复（已使用题目ID过滤）
            验证题目覆盖不同技能和组件
        /quiz/placement/submit
        /kid/placement/check?kidId={kidId}
        /user/kid/{kidId}/learning-level
        /admin/kid/{kidId}/interaction-preference
        /admin/kid/{kidId}/skill-mastery
        /game/course/tag-base-recommend
        '''
        kid_id = 715049880240197
        # topcategory_res = self.admin_course.getAlltopcategory(self.authorization_admin)
        # parentId = topcategory_res['data'][0]['id']
        # category_res = self.admin_course.getAllsubcategory(self.authorization_admin, parentId)
        # for subcategory in category_res['data']:
        #     flag = False
        #     if subcategory['level'] == "1":
        #         categoryId = subcategory['id']
        #         courselistAll = self.admin_course.course_listAll(self.authorization_admin, categoryId)
        #         for course in courselistAll['data']:
        #             course_id = course['id']
        #             course_name = course['name']
        #             course_details_res = self.admin_course.course_details(self.authorization_admin, course_id)['data']['course']
        #             if all('L1' in kill for kill in course_details_res['skillList']):
        #                 flag = True
        #                 break
        #     if flag:
        #         break
        course_id = 648882319298629
        pl = {
            "count": 3,
            "kidId": kid_id,
            "quizType": "LESSON",
            "courseId": course_id
        }
        question_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]
        quizId = question_res['quizId']
        questions = question_res['questions']

        # if len(questions) < 3:
        #     questions_res = self.admin_quiz.quiz_questions(self.authorization, course_name)
        #     if len(questions_res['data']['content']) >= 3:
        #         status_res = DataFrame(questions_res['data']['content'])['status'].tolist()
        #         if status_res.count(1) + status_res.count(0) >= 3:
        #             for question in questions_res['data']['content']:
        #                 if question['status'] == 0:
        #                     questionId = question['id']
        #                     self.admin_quiz.quiz_question_status(self.authorization, questionId, status=1)
        #     else:
        #         course_skills = self.admin_course.getByCourseIds(self.authorization, course_id)['data'][0]['skills']
        #         lecture_info_res = self.ai_server.lecture_info(self.authorization, course_id)
        #         knowledge_points = lecture_info_res['data']['knowledge_points']
        #         learning_objectives = lecture_info_res['data']['learning_objectives']
        #         assessment = lecture_info_res['data']['assessment']
        #         pl1 = {
        #             "lecture_id": course_id,
        #             "skill_ids": course_skills,
        #             "language": "en",
        #             "learning_objectives": learning_objectives,
        #             "assessment": assessment,
        #             "knowledge_points": knowledge_points
        #         }
        #         lecture_quiz_res = self.ai_server.plan_lecture_quiz(self.authorization, **pl1)
        #         reference_image = lecture_quiz_res['data']['reference_image']['url']
        #         questions_plan = lecture_quiz_res['data']['questions_plan']
        #         questionPlan = []
        #         for question in questions_plan:
        #             questionPlan.append({
        #                 "questionType": question["question_type"],
        #                 "taskDescription": question["task_description"],
        #                 "difficulty": question["difficulty"],
        #                 "skill": question["skill_id"],
        #                 "knowledgePoint": question["knowledge_point"],
        #             })
        #         generate_res = self.admin_quiz.generate_question(self.authorization, course_id, questionPlan,
        #                                                          reference_image)
        #         assert generate_res['message'] == "success"
        #         for i in range(60):
        #             questions_res = self.admin_quiz.quiz_questions(self.authorization, course_name)
        #             status_res = DataFrame(questions_res['data']['content'])['status'].tolist()
        #             if status_res.count(1) + status_res.count(0) >= 3:
        #                 for question in questions_res['data']['content']:
        #                     if question['status'] == 0:
        #                         questionId = question['id']
        #                         self.admin_quiz.quiz_question_status(self.authorization, questionId, status=1)
        #                 break
        #             else:
        #                 time.sleep(1)

        question_res1 = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]
        quizId1 = question_res1['quizId']
        questions1 = question_res1['questions']

        answers = []
        for question in questions1[:3]:
            assert question['difficulty'] == 'L1'
            questionContent = json.loads(question['questionContent'])
            if 'answers' in questionContent:
                userAnswer = questionContent['answers']
                correctAnswer = questionContent['answers']
            elif 'answer' in questionContent:
                userAnswer = questionContent['answer']
                correctAnswer = questionContent['answer']
            else:
                userAnswer = ''
                correctAnswer = ''
            answers.append(
                {
                    "quizId": quizId1,
                    "questionId": question['id'],
                    "questionSeqNo": questions1.index(question),
                    "question": questionContent['question'],
                    "userAnswer": ','.join(userAnswer),
                    "correctAnswer": correctAnswer,
                    "isCorrect": True,
                    "skillTags": [
                        question['skill']
                    ],
                    "completeTimeStamp": 0
                }
            )
        lesson_res = self.quiz.lessonSubmit(self.authorization, kid_id, course_id, answers)
        # assert lesson_res['message'] == 'success'

        learninglevel_res = self.user.getLearningLevel(self.authorization, kid_id)
        assert learninglevel_res['message'] == 'success'
        user_after_level = learninglevel_res['data']['learningLevel']

        tags_res = self.admin_kid.getKidTags(self.authorization, kid_id)
        assert tags_res['data']['childAge'] == 8
        assert tags_res['data']['learningLevel'] == user_after_level
        assert tags_res['data']['kidId'] == str(kid_id)
        lp_res = self.kid.getLearningProgress(self.authorization, kid_id)
        assert lp_res['data']['learningLevel'] == user_after_level
        assert lp_res['data']['kidId'] == kid_id
        assert lp_res['data']['valueOld']
        assert lp_res['data']['valueNew']
        assert lp_res['data']['effortPercent']
        assert lp_res['data']['masteryPercent'] == 0.0
        assert lp_res['data']['targetSlot'] == 8
        assert lp_res['data']['masteredSlot'] == 0

        ip_res = self.admin_kid.getInteractionPreference(self.authorization, kid_id)
        assert ip_res['data']['kidId'] == str(kid_id)
        assert ip_res['data']['preferences'] == []
        sm_res = self.admin_kid.getSkillMastery(self.authorization, kid_id)
        assert sm_res['data']['kidId'] == str(kid_id)
        assert sm_res['data']['skillMasteryMap']
        recommends_res = self.course.course_recommends(self.authorization, kid_id, user_after_level)
        for course in recommends_res['data']:
            assert course['difficulty'] == user_after_level

    def test_course_positive_quiz_lesson_score_check(self, getSecondekidId):
        '''问卷调查-定级-'''
        kid_id = getSecondekidId

        sm_res_before = self.admin_kid.getSkillMastery(self.authorization, kid_id)
        assert sm_res_before['data']['kidId'] == str(kid_id)

        L1_courses = self.admin_course.course_listAll(self.authorization, '641364208128069')['data']
        for course in L1_courses:
            if 'Letter Recognition-L1' in course['skillList']:
                course_id = course['id']
                break
        pl = {
            "count": 36,
            "kidId": kid_id,
            "quizType": "LESSON",
            "courseId": course_id
        }
        question_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]
        quizId = question_res['quizId']
        questions = question_res['questions']

        answers = []
        for _question in questions:
            if _question['skill'] == 'Letter Recognition-L1':
                assert _question['difficulty'] == 'L1'
                questionContent = json.loads(_question['questionContent'])
                if 'answers' in questionContent:
                    userAnswer = questionContent['answers']
                    correctAnswer = questionContent['answers']
                elif 'answer' in questionContent:
                    userAnswer = questionContent['answer']
                    correctAnswer = questionContent['answer']
                else:
                    userAnswer = ''
                    correctAnswer = ''
                _skill = _question['skill']
                question = _question
                break
        answers.append(
            {
                "quizId": quizId,
                "questionId": question['id'],
                "questionSeqNo": 0,
                "question": questionContent['question'],
                "userAnswer": 'yes',
                "correctAnswer": 'yes',
                "isCorrect": True,
                "skillTags": [_skill],
                "completeTimeStamp": 0
            }
        )
        lesson_res = self.quiz.lessonSubmit(self.authorization, kid_id, course_id, answers)
        assert lesson_res['message'] == 'success'

        sm_res_after = self.admin_kid.getSkillMastery(self.authorization, kid_id)
        assert sm_res_after['data']['kidId'] == str(kid_id)
        assert sm_res_after['data']['skillMasteryMap'][_skill]['masteryScore'] == 20.0
        assert sm_res_after['data']['skillMasteryMap'][_skill]['masteryState'] == 'Weak'

        for _question in questions:
            if _question['skill'] == _skill:
                question_second = _question
                break

        answers1 = []
        questionContent = json.loads(question_second['questionContent'])
        if 'answers' in questionContent:
            userAnswer = questionContent['answers']
            correctAnswer = questionContent['answers']
        elif 'answer' in questionContent:
            userAnswer = questionContent['answer']
            correctAnswer = questionContent['answer']
        else:
            userAnswer = ''
            correctAnswer = ''
        answers1.append(
            {
                "quizId": quizId,
                "questionId": question_second['id'],
                "questionSeqNo": 0,
                "question": questionContent['question'],
                "userAnswer": 'yes',
                "correctAnswer": 'yes',
                "isCorrect": True,
                "skillTags": [_skill],
                "completeTimeStamp": 0
            }
        )
        lesson_res = self.quiz.lessonSubmit(self.authorization, kid_id, course_id, answers1)
        assert lesson_res['message'] == 'success'

        sm_res_after = self.admin_kid.getSkillMastery(self.authorization, kid_id)
        assert sm_res_after['data']['kidId'] == str(kid_id)
        assert sm_res_after['data']['skillMasteryMap'][_skill]['masteryScore'] == 32.0
        assert sm_res_after['data']['skillMasteryMap'][_skill]['masteryState'] == 'Practicing'

    def test_course_positive_quiz_lesson_score_check1(self, getSecondekidId):
        '''问卷调查-定级-'''
        kid_id = getSecondekidId

        sm_res_before = self.admin_kid.getSkillMastery(self.authorization, kid_id)
        assert sm_res_before['data']['kidId'] == str(kid_id)

        # L1_courses = self.admin_course.course_listAll(self.authorization, '641364208128069')['data']
        # for course in L1_courses:
        #     if course['name'] == 'Colors':
        #         course_id = course['id']
        #         break
        topcategory_res = self.admin_course.getAlltopcategory(self.authorization_admin)
        parentId = topcategory_res['data'][0]['id']
        category_res = self.admin_course.getAllsubcategory(self.authorization_admin, parentId)
        for subcategory in category_res['data']:
            flag = False
            if subcategory['level'] == "1":
                categoryId = subcategory['id']
                courselistAll = self.admin_course.course_listAll(self.authorization_admin, categoryId)
                for course in courselistAll['data']:
                    course_id = course['id']
                    course_details_res = self.admin_course.course_details(self.authorization_admin, course_id)['data']['course']
                    if all('L1' in kill for kill in course_details_res['skillList']):
                        flag = True
                        break
            if flag:
                break


        pl = {
            "count": 36,
            "kidId": kid_id,
            "quizType": "LESSON",
            "courseId": course_id
        }
        question_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]
        quizId = question_res['quizId']
        questions = question_res['questions']
        # for _question in questions:
        #     if _question['skill'] == 'Letter Recognition-L1':
        #         assert _question['difficulty'] == 'L1'
        #         question = _question
        #         break

        question = questions[0]
        answers = []
        questionContent = json.loads(question['questionContent'])
        if 'answers' in questionContent:
            userAnswer = questionContent['answers']
            correctAnswer = questionContent['answers']
        elif 'answer' in questionContent:
            userAnswer = questionContent['answer']
            correctAnswer = questionContent['answer']
        else:
            userAnswer = ''
            correctAnswer = ''
        _skill = question['skill']
        answers.append(
            {
                "quizId": quizId,
                "questionId": question['id'],
                "questionSeqNo": 0,
                "question": questionContent['question'],
                "userAnswer": 'yes',
                "correctAnswer": 'yes',
                "isCorrect": True,
                "skillTags": [_skill],
                "completeTimeStamp": 0
            }
        )
        lesson_res = self.quiz.lessonSubmit(self.authorization, kid_id, course_id, answers)
        assert lesson_res['message'] == 'success'

    def test_course_positive_quiz_promotion(self):
        '''问卷调查-定级-'''
        '''
        晋级流程测试
        /kid/placement/check?kidId={kidId}
        /course/promotion/check?kidId={kidId}
            已掌握80%以上必要技能：返回有晋级资格
            未掌握80%必要技能：返回无晋级资格
            验证返回当前等级和目标等级
            验证返回已掌握技能数和总技能数
        /quiz/fetch-questions(PLACEMENT（定级）PROMOTION（晋级）LESSON（课后）)
        /quiz/promotion/submit
        /user/kid/{kidId}/learning-level
        /admin/kid/{kidId}/tags
        /kid/{kidId}/learning-progress
        /user/kid/{kidId}/learning-level
        /game/course/tag-base-recommend
        '''
        kid_id = 715049880240197

        eligible_res = self.course.promotion_check(self.authorization, kid_id)
        currentLevel = eligible_res['data']['currentLevel']
        pl = {
            "quizType": "PROMOTION",
            "kidId": kid_id,
            "count": 12
        }
        questions_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]
        assert questions_res['level'] == currentLevel
        quizId = questions_res['quizId']
        questions = questions_res['questions']
        answers = []
        for question in questions[:2]:
            assert question['difficulty'] == currentLevel
            questionContent = json.loads(question['questionContent'])
            if 'answers' in questionContent:
                userAnswer = questionContent['answers']
                correctAnswer = questionContent['answers']
            elif 'answer' in questionContent:
                userAnswer = questionContent['answer']
                correctAnswer = questionContent['answer']
            else:
                userAnswer = ''
                correctAnswer = ''
            answers.append(
                {
                    "quizId": quizId,
                    "questionId": question['id'],
                    "questionSeqNo": questions.index(question),
                    "question": questionContent['question'],
                    "userAnswer": userAnswer,
                    "correctAnswer": correctAnswer,
                    "isCorrect": True,
                    "skillTags": [
                        question['skill']
                    ],
                    "completeTimeStamp": 1699123456789
                }
            )

        '''
            {
        "quizId": "123456789",
        "questionId": 111,
        "questionSeqNo": 1,
        "userAnswer": "A",
        "correctAnswer": "A",
        "isCorrect": true,
        "skillTags": ["Phonics-L3-Component1"],
        "completeTimeStamp": 1699123456789
        }
        '''
        eligible_res = self.course.promotion_check(self.authorization, kid_id)

        promotion_res = self.quiz.promotionPubmit(self.authorization, kid_id, answers)
        assert promotion_res['message'] == 'success'
        # assert promotion_res['data']['previousLevel'] == 'L1'
        # assert promotion_res['data']['newLevel'] == 'L2'
        # assert promotion_res['data']['promotionSuccess'] == 'success'

        learninglevel_res = self.user.getLearningLevel(self.authorization, kidId=kid_id)
        assert learninglevel_res['message'] == 'success'
        user_after_level = learninglevel_res['data']['learningLevel']

        # tags_res = self.admin_kid.getKidTags(self.authorization, kid_id)
        # assert tags_res['data']['childAge'] == 8
        # assert tags_res['data']['learningLevel'] == user_after_level
        # assert tags_res['data']['kidId'] == str(kid_id)

        lp_res = self.kid.getLearningProgress(self.authorization, kid_id)
        assert lp_res['data']['learningLevel'] == user_after_level
        assert lp_res['data']['kidId'] == kid_id
        assert lp_res['data']['valueOld']
        assert lp_res['data']['valueNew']
        assert lp_res['data']['effortPercent']
        assert lp_res['data']['masteryPercent'] == 0.0
        assert lp_res['data']['targetSlot'] == 8
        assert lp_res['data']['masteredSlot'] == 0

        ip_res = self.admin_kid.getInteractionPreference(self.authorization, kid_id)
        assert ip_res['data']['kidId'] == str(kid_id)
        assert ip_res['data']['preferences'] == []

        sm_res = self.admin_kid.getSkillMastery(self.authorization, kid_id)
        assert sm_res['data']['kidId'] == str(kid_id)
        assert sm_res['data']['skillMasteryMap']

        recommends_res = self.course.course_recommends(self.authorization, kid_id, user_after_level)
        for course in recommends_res['data']:
            assert course['difficulty'] == user_after_level

    def test_check_kid_status(self, getSecondekidId):
        kid_id = getSecondekidId
        lp_res = self.kid.getLearningProgress(self.authorization, kid_id)
        assert lp_res
        eligible_res = self.course.promotion_check(self.authorization, kid_id)
        assert eligible_res

        ip_res = self.admin_kid.getInteractionPreference(self.authorization, kid_id)
        assert ip_res['data']['kidId'] == str(kid_id)
        # assert ip_res['data']['preferences'] == []

        user_level = 'L2'
        pl = {
            "count": 12,
            "kidId": kid_id,
            "levelList": ['L2']
        }
        question_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]

        course_id=648473290956869
        pl = {
            "count": 3,
            "kidId": kid_id,
            "quizType": "LESSON",
            "courseId": course_id
        }
        question_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]


        pl = {
            "quizType": "PROMOTION",
            "kidId": kid_id,
            "count": 12
        }
        questions_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]

        recommends_res = self.course.course_recommends(self.authorization, kid_id, user_level)
        for course in recommends_res['data']:
            assert course['difficulty'] == user_level

    @pytest.mark.release
    def test_course_positive_course_rating_ok(self):
        """保存课程评价-正向用例"""
        # Normal课程资源列表
        course_id = self.school.getNormalcourse(self.authorization)["data"]['content'][0]['id']
        # 保存课程评价
        res = self.course.save_course_rating(self.authorization, course_id, self.kid_id, 3)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['userId'] == int(self.userId)
        assert res['data']['kidId'] == self.kid_id
        assert res['data']['courseId'] == course_id
        assert res['data']['rating'] == 3

    @pytest.mark.release
    def test_course_permission_course_rating(self):
        """保存课程评价-权限测试"""
        res = self.course.save_course_rating('', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_course_positive_course_ratings_ok(self):
        """根据课程ID列表获取评价信息-正向用例"""
        # Normal课程资源列表
        course_id = self.school.getNormalcourse(self.authorization)["data"]['content'][0]['id']
        # 根据课程ID列表获取评价信息
        res = self.course.course_ratings(self.authorization, [course_id], self.kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_course_permission_course_ratings(self):
        """根据课程ID列表获取评价信息-权限测试"""
        res = self.course.course_ratings('', code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize('rate', [1,2,3])
    def test_course_course_rating_total_ok(self, rate):
        """保存获取课程评价-正向用例"""
        # Normal课程资源列表
        course_res = self.school.getNormalcourse(self.authorization)["data"]['content']
        for course in course_res:
            course_id = course['id']
            # 根据课程ID列表获取评价信息
            rating_res = self.course.course_ratings(self.authorization, [course_id], self.kid_id)
            # 如果课程未被评价过则进行评价
            if not rating_res['data'][str(course_id)]['hasRated']:
                # 保存课程评价
                res = self.course.save_course_rating(self.authorization, course_id, self.kid_id, rate)
                assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
                assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
                assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
                assert res['data']['userId'] == int(self.userId)
                assert res['data']['kidId'] == self.kid_id
                assert res['data']['courseId'] == course_id
                assert res['data']['rating'] == rate
                break
        else:
            assert False, "未找到未评价的课程！"
        # 保存课程评价后，获取评价信息，验证保存课程评价成功
        rating_res = self.course.course_ratings(self.authorization, [course_id], self.kid_id)
        assert rating_res['data'][str(course_id)]['hasRated']
        assert rating_res['data'][str(course_id)]['rating'] == rate