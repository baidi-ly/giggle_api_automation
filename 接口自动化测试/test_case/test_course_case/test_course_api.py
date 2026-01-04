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
        self.admin_auth = self.admin_course.get_admin_authorization()[0]

        kids_res = self.kid.getKids(self.authorization)
        for kid in kids_res['data']:
            if kid['name'] == 'New Kid':
                self.kid_id = kid['id']
                break

        # 批量新增等级技能
        self.skillIds = []
        for i in range(3):
            educationType = "dibo_test" + self.now + str(i)
            pl = {
                "educationType": educationType,
            }
            skill_id = self.admin_level.createLevelSkill(self.authorization, **pl)['data']['id']
            self.skillIds.append(skill_id)

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

    @pytest.fixture(scope='class')
    def courseId_fixture(self):
        """获取课程详情包括版本信息"""
        # 获取顶层课程目录列表
        topcategory_res = self.admin_course.getAlltopcategory(self.admin_auth)
        for category in topcategory_res['data']:
            parentId = category['id']
            # 获取课程子目录列表
            category_res1 = self.admin_course.getAllsubcategory(self.admin_auth, parentId)
            for subcategory in category_res1['data']:
                parentId1 = subcategory['id']
                category_res2 = self.admin_course.getAllsubcategory(self.admin_auth, parentId1)
                for subcategory2 in category_res2['data']:
                    categoryId = subcategory2['id']
                    # 获取分类下所有课程
                    courselistAll = self.admin_course.course_listAll(self.admin_auth, categoryId)['data']
                    if not courselistAll:
                        continue
                    course_id = DataFrame(courselistAll)['id'].tolist()[0]
                    return course_id

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

    @pytest.fixture(scope="class")
    def getSecondekidId(self):
        '''类前置 - 获取kidId'''
        kid_res = self.kid.getKids(self.authorization)['data']
        for kid in kid_res:
            if kid['name'] == "New Kid":
                kid_id = kid['id']
                break
        yield kid_id

    @pytest.fixture(scope='function')
    def voiceMultilingual_fixture(self, courseId_fixture):
        '''新增语音文案'''
        # 获取课程详情包括版本信息
        course_id = courseId_fixture
        # 新增语音文案
        key = 'dibo_test' + self.now
        pl = {
            "key": key,  # String，必填：环节标识（比如某一页、某一步骤的key）
            "targetLanguage": "en"  # String，必填：目标语言代码（如 "en"、"ar"）
        }
        add_res = self.admin_course.addVoiceMultilingual(self.authorization, course_id, **pl)
        assert add_res['message'] == 'success', "新增语音文案失败！"
        # 分页查询语音文案列表，新增语音文案成功
        search_res1 = self.admin_course.voiceMultilinguals(self.authorization, course_id, key=key, size=100)
        for item in search_res1['data']['content']:
            if item['key'] == key:
                voice_id = item['id']
                break
        else:
            assert False, "新增语音文案失败，列表未查询到！"

        yield course_id, voice_id

        # 删除语音文案
        delete_res = self.admin_course.deleteVoiceMultilingual(self.authorization, voice_id)
        assert delete_res['message'] == 'success', "删除语音文案失败！"

    @pytest.mark.smoke
    def test_course_blockedCourseIds_login(self):
        """获取屏蔽的课程ID列表"""
        # 获取屏蔽的课程ID列表
        stats_res = self.course.blockedCourseIds(self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["blockedIds"]

    def test_course_blockedCourseIds_customer(self):
        """获取屏蔽的课程ID列表"""
        # 获取屏蔽的课程ID列表
        stats_res = self.course.blockedCourseIds('')
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["blockedIds"]

    @pytest.mark.smoke
    def test_course_positive_recommendation_ok(self):
        """获取课程推荐-正向用例"""
        # Normal课程资源列表
        course_id = self.school.getNormalcourse(self.authorization)["data"]['content'][0]['id']
        # 获取孩子数据
        kid_id = self.kid.getKids(self.authorization)["data"][0]['id']
        pl = {
            "currentCourseId": course_id,
            "includeReasonInfo": False,
            "kidId": kid_id,
            "recommendCount": 2
        }
        # 获取课程推荐
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
        res = self.course.recommendation(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_course_positive_getTags_ok(self):
        """查询所有推荐和热门标签-正向用例"""
        # 查询所有推荐和热门标签
        res = self.course.getTags(self.authorization)
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
    def test_course_permission_getTags(self, desc, value):
        """查询所有推荐和热门标签-权限测试"""
        res = self.course.getTags(value)
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_course_positive_getAlbums_ok(self):
        """查询所有生效中的专辑及其标签-正向用例"""
        '''
        /course/tag/create
        POST /course/album/create
        '''
        # 查询所有生效中的专辑及其标签
        res = self.course.course_albums(self.authorization)
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
    def test_course_permission_getAlbums(self, desc, value):
        """查询所有生效中的专辑及其标签-权限测试"""
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
        # 获取课程推荐列表
        res = self.course.course_recommends(self.authorization, self.kid_id, learningLevel)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        course_recommends = res['data']
        if course_recommends:
            for course in course_recommends:
                assert course['difficulty'] == learningLevel

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
        # 获取课程推荐列表
        res = self.course.course_public_recommends(self.authorization, learningLevel)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        course_public_recommends = res['data']
        if course_public_recommends:
            for course in course_public_recommends:
                assert course['difficulty'] == learningLevel

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
        # 创建课程用户标签
        tagId = createCourseTag_method
        # 根据标签ID查询对应的课程列表
        res = self.course.coursesByTag(self.authorization, tagId)
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
    def test_course_permission_coursesByTag(self, desc, value, createCourseTag_method):
        """根据标签ID查询对应的课程列表-权限测试"""
        # 创建课程用户标签
        tagId = createCourseTag_method
        # 根据标签ID查询对应的课程列表
        res = self.course.coursesByTag(value, tagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    def test_course_positive_quiz_placement(self, kid_data_session):
        '''学生定级 - 定级quiz'''
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
        # 创建测试学生
        kid_id = kid_data_session

        # 查询是否需要定级
        check_res2 = self.kid.check_placement(self.authorization, kid_id)
        assert check_res2['data']['currentLevel'] == 'L1'
        assert check_res2['data']['needPlacement'] == True
        assert check_res2['data']['initialLevel'] == 'L1'
        assert check_res2['data']['levelRange'] == {'max': 'L5', 'min': 'L1'}

        placementLevel = 'L1'
        levelList = [placementLevel]
        # 根据题库获取Quiz题目
        pl = {
            "count": 12,
            "kidId": kid_id,
            "levelList": levelList
        }
        question_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]
        assert question_res['level'] == 'L1', "获取定级quiz等级有误！"
        quizId = question_res['quizId']
        questions = question_res['questions']
        assert len(questions) == 12, "获取定级quiz数量有误！"

        # 拼接quiz答案
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
        # 提交定级Quiz
        placement_res = self.quiz.placementSubmit(self.authorization, kid_id, placementLevel, answers)
        assert placement_res['message'] == 'success', "提交定级Quiz失败！"

        # 再次查询是否需要定级
        check_res2 = self.kid.check_placement(self.authorization, kid_id)
        assert check_res2['data']['currentLevel'] == 'L1'
        assert check_res2['data']['needPlacement'] == False
        assert check_res2['data']['initialLevel'] == 'L1'
        assert check_res2['data']['levelRange'] == {'max': 'L5', 'min': 'L1'}
        # 获取孩子的学习水平
        learninglevel_res = self.user.getLearningLevel(self.authorization, kid_id)
        assert learninglevel_res['data']['learningLevel'] == 'L1'
        tags_res = self.admin_kid.getKidTags(self.authorization, kid_id)
        assert tags_res['data']['childAge'] == 6
        assert tags_res['data']['kidId'] == str(kid_id)
        assert tags_res['data']['learningLevel'] == 'L1'
        # 查询晋级进度条
        lp_res = self.kid.getLearningProgress(self.authorization, kid_id)
        assert lp_res['data']['kidId'] == kid_id
        assert lp_res['data']['learningLevel'] == 'L1'
        assert lp_res['data']['valueOld']
        assert lp_res['data']['valueNew']
        assert lp_res['data']['masteryPercent']
        # 查询孩子互动偏好
        ip_res = self.admin_kid.getInteractionPreference(self.authorization, kid_id)
        assert ip_res['data']['kidId'] == str(kid_id)
        assert ip_res['data']['preferences'] == []
        # 获取学生技能掌握程度
        sm_res = self.admin_kid.getSkillMastery(self.authorization, kid_id)
        assert sm_res['data']['kidId'] == str(kid_id)
        assert sm_res['data']['skillMasteryMap']
        # 获取课程推荐列表
        recommends_res = self.course.course_recommends(self.authorization, kid_id, placementLevel)['data']
        for course in recommends_res:
            assert course['difficulty'] == 'L1'

    def test_course_positive_quiz_lesson(self, kid_data_session, get_course_ids_session):
        '''学生升级 - 课后quiz'''
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
        # 创建测试学生
        kid_id = kid_data_session
        # 获取课程详情包括版本信息
        course_id = get_course_ids_session
        pl = {
            "count": 3,
            "kidId": kid_id,
            "quizType": "LESSON",
            "courseId": course_id
        }
        # 根据题库获取Quiz题目
        question_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]
        quizId = question_res['quizId']
        questions = question_res['questions']

        # 如果当前课程的Quiz题目不足3个
        if len(questions) < 3:
            course_name = self.admin_course.course_details(self.admin_auth, course_id)['data']['course']['name']
            questions_res = self.admin_quiz.quiz_questions(self.authorization, course_name)
            if len(questions_res['data']['content']) >= 3:
                status_res = DataFrame(questions_res['data']['content'])['status'].tolist()
                if status_res.count(1) + status_res.count(0) >= 3:
                    for question in questions_res['data']['content']:
                        if question['status'] == 0:
                            questionId = question['id']
                            self.admin_quiz.quiz_question_status(self.authorization, questionId, status=1)
            else:
                course_skills = self.admin_course.getByCourseIds(self.authorization, course_id)['data'][0]['skills']
                lecture_info_res = self.ai_server.lecture_info(self.authorization, course_id)
                knowledge_points = lecture_info_res['data']['knowledge_points']
                learning_objectives = lecture_info_res['data']['learning_objectives']
                assessment = lecture_info_res['data']['assessment']
                pl1 = {
                    "lecture_id": course_id,
                    "skill_ids": course_skills,
                    "language": "en",
                    "learning_objectives": learning_objectives,
                    "assessment": assessment,
                    "knowledge_points": knowledge_points
                }
                lecture_quiz_res = self.ai_server.plan_lecture_quiz(self.authorization, **pl1)
                reference_image = lecture_quiz_res['data']['reference_image']['url']
                questions_plan = lecture_quiz_res['data']['questions_plan']
                questionPlan = []
                for question in questions_plan:
                    questionPlan.append({
                        "questionType": question["question_type"],
                        "taskDescription": question["task_description"],
                        "difficulty": question["difficulty"],
                        "skill": question["skill_id"],
                        "knowledgePoint": question["knowledge_point"],
                    })
                generate_res = self.admin_quiz.generate_question(self.authorization, course_id, questionPlan,
                                                                 reference_image)
                assert generate_res['message'] == "success"
                for i in range(60):
                    questions_res = self.admin_quiz.quiz_questions(self.authorization, course_name)
                    status_res = DataFrame(questions_res['data']['content'])['status'].tolist()
                    if status_res.count(1) + status_res.count(0) >= 3:
                        for question in questions_res['data']['content']:
                            if question['status'] == 0:
                                questionId = question['id']
                                self.admin_quiz.quiz_question_status(self.authorization, questionId, status=1)
                        break
                    else:
                        time.sleep(1)

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
        assert lesson_res['message'] == 'success'
        # 获取孩子的学习水平
        learninglevel_res = self.user.getLearningLevel(self.authorization, kid_id)
        assert learninglevel_res['message'] == 'success'
        user_after_level = learninglevel_res['data']['learningLevel']
        # 获取用户标签
        tags_res = self.admin_kid.getKidTags(self.authorization, kid_id)
        assert tags_res['data']['childAge'] == 8
        assert tags_res['data']['learningLevel'] == user_after_level
        assert tags_res['data']['kidId'] == str(kid_id)
        # 查询晋级进度条
        lp_res = self.kid.getLearningProgress(self.authorization, kid_id)
        assert lp_res['data']['learningLevel'] == user_after_level
        assert lp_res['data']['kidId'] == kid_id
        assert lp_res['data']['valueOld']
        assert lp_res['data']['valueNew']
        assert lp_res['data']['effortPercent']
        assert lp_res['data']['masteryPercent'] == 0.0
        assert lp_res['data']['targetSlot'] == 8
        assert lp_res['data']['masteredSlot'] == 0
        # 查询孩子互动偏好
        ip_res = self.admin_kid.getInteractionPreference(self.authorization, kid_id)
        assert ip_res['data']['kidId'] == str(kid_id)
        assert ip_res['data']['preferences'] == []
        # 获取学生技能掌握程度
        sm_res = self.admin_kid.getSkillMastery(self.authorization, kid_id)
        assert sm_res['data']['kidId'] == str(kid_id)
        assert sm_res['data']['skillMasteryMap']
        # 获取课程推荐列表
        recommends_res = self.course.course_recommends(self.authorization, kid_id, user_after_level)
        for course in recommends_res['data']:
            assert course['difficulty'] == user_after_level

    def test_course_positive_quiz_lesson_score_check(self, getSecondekidId):
        '''学生升级 - 升级quiz'''
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

    def test_course_positive_quiz_promotion(self, kid_data_session):
        '''学生升级 - 升级quiz - 晋级流程测试'''
        # 创建测试学生
        kid_id = kid_data_session
        # 查询晋级资格
        eligible_res = self.course.promotion_check(self.authorization, kid_id)
        currentLevel = eligible_res['data']['currentLevel']
        pl = {
            "quizType": "PROMOTION",
            "kidId": kid_id,
            "count": 12
        }
        # 根据题库获取Quiz题目
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

    def test_check_kid_status(self):
        # kid_id = getSecondekidId
        kid_id = 751101058991429
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

    @pytest.mark.smoke
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

    @pytest.mark.smoke
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

    @pytest.mark.smoke
    @pytest.mark.parametrize('rate', [1, 2, 3])
    def test_course_course_rating_total_ok(self, rate, get_course_ids_session, kid_data_session):
        """保存获取课程评价-正向用例"""
        # 获取课程详情包括版本信息
        courseIds = get_course_ids_session
        # 创建测试学生
        kid_id, kid_name = kid_data_session
        for course_id in courseIds:
            # 根据课程ID列表获取评价信息
            rating_res = self.course.course_ratings(self.authorization, [course_id], kid_id)
            # 如果课程未被评价过则进行评价
            if not rating_res['data'][str(course_id)]['hasRated']:
                # 保存课程评价
                res = self.course.save_course_rating(self.authorization, course_id, kid_id, rate)
                assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
                assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
                assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
                assert res['data']['userId'] == int(self.userId)
                assert res['data']['kidId'] == kid_id
                assert res['data']['courseId'] == int(course_id)
                assert res['data']['rating'] == rate
                break
        else:
            assert False, "未找到未评价的课程！"
        # 保存课程评价后，获取评价信息，验证保存课程评价成功
        rating_res = self.course.course_ratings(self.authorization, [course_id], kid_id)
        assert rating_res['data'][str(course_id)]['hasRated']
        assert rating_res['data'][str(course_id)]['rating'] == rate

    @pytest.mark.smoke
    @pytest.mark.parametrize('learningLevel', ['L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L8', 'L9', 'L10', 'L11', 'L12', 'L13', 'L14', 'L15', 'L16', 'L17', 'L18','L19', 'L20'])
    def test_course_recommend_list_check(self, learningLevel, kid_data_session):
        '''通过kid.learninglevel匹配课程difficulty,过滤出来的课程按旧level+no正序排序返回'''
        # 创建测试学生
        kid_id = kid_data_session
        # 获取课程推荐列表（需要认证）
        recommends_res = self.course.course_recommends(self.authorization, kid_id, learningLevel)
        no = 0  # 校验书籍正序排序返回
        ids = []
        for course in recommends_res['data']:
            assert course['difficulty'] == learningLevel
            course_no = course['no']
            id = course['categoryId']
            if id in ids:
                assert course_no > no
                no = course_no
            else:
                ids.append(id)
                no = 0
                assert course_no > no
                no = course_no

    @pytest.mark.smoke
    @pytest.mark.parametrize('learningLevel',
                             ['L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L8', 'L9', 'L10', 'L11', 'L12', 'L13', 'L14',
                              'L15', 'L16', 'L17', 'L18', 'L19', 'L20'])
    def test_course_public_recommends_check(self, learningLevel):
        '''通过kid.learninglevel匹配课程difficulty,过滤出来的课程按旧level+no正序排序返回'''
        # 获取课程推荐列表（公开接口）
        recommends_res = self.course.course_public_recommends(self.authorization, learningLevel)
        no = 0  # 校验书籍正序排序返回
        ids = []
        for course in recommends_res['data']:
            assert course['difficulty'] == learningLevel
            course_no = course['no']
            id = course['categoryId']
            if id in ids:
                assert course_no > no
                no = course_no
            else:
                ids.append(id)
                no = 0
                assert course_no > no
                no = course_no

    @pytest.mark.smoke
    @pytest.mark.parametrize('learningLevel',
                             ['L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L8', 'L9', 'L10', 'L11', 'L12', 'L13', 'L14',
                              'L15', 'L16', 'L17', 'L18', 'L19', 'L20'])
    def test_course_positive_getFixOrderRecommend_ok(self, learningLevel):
        """获取推荐课程列表-正向用例"""
        # 获取推荐课程列表
        recommends_res = self.course.getFixOrderRecommend(self.authorization, learningLevel=learningLevel)
        assert recommends_res['message'] == 'success'
        if recommends_res['data']:
            categoryLevel = 0 # 校验书籍正序排序返回
            for course in recommends_res['data']:
                assert course['difficulty'] == learningLevel
                course_no = course['courseNo']
                categoryName = int(course['categoryName'].split('-')[-1])
                # 如果当前level发生改变，则先判断level等级增加，再将初始no清零
                if categoryLevel != categoryName:
                    assert categoryName>categoryLevel
                    categoryLevel = categoryName
                    no = 0
                assert course_no > no
                no = course_no

    @pytest.mark.smoke
    def test_game_positive_voiceMultilinguals_item(self, voiceMultilingual_fixture):
        """查询课程策略配置-正向用例"""
        # 新增语音文案
        course_id, voice_id = voiceMultilingual_fixture
        # 查询课程语音列表
        voice_res = self.course.appVoiceMultilinguals(self.authorization, course_id)
        for item in voice_res['data']:
            if item['id'] == voice_id:
                item1 = item
                break
        else:
            assert False, "新增语音文案失败，列表未查询到！"

        # 分页查询语音文案列表，新增语音文案成功
        search_res1 = self.admin_course.voiceMultilinguals(self.authorization, course_id, size=100)
        for item in search_res1['data']['content']:
            if item['id'] == voice_id:
                item2 = item
                break
        else:
            assert False, "新增语音文案失败，列表未查询到！"
        # 验证课程语音文案添加成功
        assert item1 == item2, "课程语音文案添加失败！"

    @pytest.mark.release
    def test_game_positive_fetchQuestions_result_check(self, kid_data_session, get_course_ids_session):
        '''课程抽题改为根据课程id从题库中抽''' # todo
        kid_id, kid_name = kid_data_session
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
                        # 根据题库获取Quiz题目
                        quiz_ids = DataFrame(course_quiz_res['data']['content'])['id'].tolist()
                        pl = {
                            "count": 3,
                            "kidId": kid_id,
                            "quizType": "LESSON",
                            "courseId": course_id
                        }
                        question_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data']
                        for question in question_res[0]['questions']:
                            assert question['difficulty'] == course_difficulty
                            assert question['skill'] in skills or any(question['skill'].startswith(kill) for kill in skills)
                            assert question['id'] in quiz_ids
