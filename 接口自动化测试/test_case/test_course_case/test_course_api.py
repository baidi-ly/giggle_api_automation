import datetime
from time import strftime

import pytest
import sys
import os

import config
from test_case.page_api.admin.admin_course_api import AdminCourseApi
from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.school.school_api import SchoolApi

sys.path.append(os.getcwd())
sys.path.append("..")

expired_token = config.RunConfig.expired_token

@pytest.mark.Course
class TestCourse:

    def setup_class(self):
        self.course = CourseApi()
        self.school = SchoolApi()
        self.kid = KidApi()
        self.admin = AdminCourseApi()
        self.now = strftime("%Y%m%d%H%M%S")
        self.authorization = self.course.get_authorization()[0]
        self.authorization_admin = self.admin.get_authorization()[0]

        # 批量新增等级技能
        self.skillIds = []
        for i in range(3):
            educationType = "dibo_test" + self.now + str(i)
            pl = {
                "educationType": educationType,
            }
            skill_id = self.admin.createLevelSkill(self.authorization, **pl)['data']['id']
            self.skillIds.append(skill_id)

    def setup_method(self):
        '''获取kid_id'''
        self.kid_id = self.kid.getKids(self.authorization)["data"][0]['id']

    def teardown_class(self):
        '''清除所有课程用户标签测试数据'''
        try:
            for status in [0, 1]:
                pl = {"status": status}
                course_tags = self.admin.course_tag_list(self.authorization, **pl)['data']
                for course_tag in course_tags:
                    # 删除课程用户标签
                    if course_tag['name'].startswith('course_tag_test'):
                        course_tag_id = course_tag['id']
                        delete_res = self.admin.delete_course_tag(self.authorization, course_tag_id)
                        assert delete_res['data'] == '删除成功', f"接口返回data数据异常：{delete_res['data']}"
        except Exception as e:
            print(f'删除课程用户标签失败，原因是：{e}')

        try:
            # 获取所有教育类型为dibo_test开头的等级技能
            delete_skills = []
            course_skills = self.admin.course_skills(self.authorization)['data']['content']
            for course_skill in course_skills:
                if course_skill['educationType'].startswith('dibo_test'):
                    delete_skills.append(course_skill['id'])
            # 删除等级技能
            if delete_skills:
                del_res = self.admin.deleteLevelskills(self.authorization, delete_skills)
                assert del_res['code'] == 200
        except Exception as e:
            print(f'删除等级技能失败，原因是：{e}')

    @pytest.fixture(scope='function')
    def createCourseTag_method(self):
        '''方法固件 - 创建课程用户标签'''
        # 创建课程用户标签
        tag_name = 'course_tag_test' + self.now
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
        res = self.admin.create_course_tag(self.authorization, file=file, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        course_tag_id = res['data']['id']

        yield course_tag_id

        # 删除课程标签
        res = self.admin.delete_course_tag(self.authorization, course_tag_id)
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

    def test_noargs_detail_basic(self):
        """获取所有课程分级列表"""
        res = self.api.detail(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

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

    @pytest.mark.release
    def test_course_positive_getTags_ok(self):
        """查询所有推荐和热门标签-正向用例"""
        res = self.course.getTags(self.authorization)
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
            skill_id = self.admin.createLevelSkill(self.authorization, **pl)['data']['id']
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
        create_res = self.admin.create_course_tag(self.authorization, file=file, **pl)
        course_tag_id = create_res['data']['id']    # 用户标签ID

        yield course_tag_id

        # 删除课程用户标签
        res = self.admin.delete_course_tag(self.authorization, course_tag_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"

        # 删除等级技能
        del_res = self.admin.deleteLevelskills(self.authorization, skillIds)
        assert del_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{del_res['code']}】"

    @pytest.mark.release
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

    @pytest.mark.release
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

    @pytest.mark.release
    def test_course_positive_promotion_check_ok(self):
        """查询晋级资格-正向用例"""
        res = self.course.promotion_check(self.authorization, self.kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert ('eligible' and 'currentLevel' and 'targetLevel' and 'masteredSkillCount'
                and 'totalNecessarySkillCount') in res['data']

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
    def test_course_permission_promotion_check(self, desc, value):
        """查询晋级资格-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.course.promotion_check(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
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

    @pytest.mark.release
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

    @pytest.mark.release
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

    @pytest.mark.release
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

    @pytest.mark.release
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

    @pytest.mark.release
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

    @pytest.mark.release
    def test_course_positive_coursesByTag_ok(self, createCourseTag_method):
        """根据标签ID查询对应的课程列表-正向用例"""
        tagId = createCourseTag_method
        res = self.course.coursesByTag(self.authorization, tagId)
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