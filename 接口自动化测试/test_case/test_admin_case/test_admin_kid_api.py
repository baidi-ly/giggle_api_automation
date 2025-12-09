import datetime
import json
import random
import sys
import os
import time
from time import strftime

from pandas import DataFrame

import config
from test_case.page_api.admin.admin_kid_api import AdminKidApi
from test_case.page_api.admin.admin_levelskills_api import AdminLevelskillsApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.quiz.quiz_api import QuizApi
from test_case.page_api.school.school_api import SchoolApi
from test_case.page_api.user.user_api import UserApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.admin
@pytest.mark.adminKid
class TestAdminkid:

    def setup_class(self):
        self.admin_kid = AdminKidApi()
        self.authorization = self.admin_kid.get_admin_authorization()[0]

        self.kid = KidApi()
        self.user = UserApi()
        self.school = SchoolApi()
        self.quiz = QuizApi()
        self.admin_levelskills = AdminLevelskillsApi()
        self.kid_id = self.kid.getKids(self.authorization)["data"][0]['id']

        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.smoke
    def test_admin_kid_positive_getInteractionPreference_ok(self):
        """查询孩子互动偏好-正向用例"""
        res = self.admin_kid.getInteractionPreference(self.authorization, self.kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['kidId'] == str(self.kid_id), f"接口返回data数据异常：{res['data']}"
        assert 'preferences' in res['data']

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
    def test_admin_kid_permission_getInteractionPreference(self, desc, value):
        """查询孩子互动偏好-权限测试"""
        res = self.admin_kid.getInteractionPreference(value, 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_kid_positive_getSkillMastery_ok(self):
        """获取学生技能掌握程度-正向用例"""
        res = self.admin_kid.getSkillMastery(self.authorization, self.kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['kidId'] == str(self.kid_id), f"接口返回data数据异常：{res['data']}"
        assert 'skillMasteryMap' in res['data']

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
    def test_admin_kid_permission_getSkillMastery(self, desc, value):
        """获取学生技能掌握程度-权限测试"""
        res = self.admin_kid.getSkillMastery(value, 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_kid_positive_getKidTags_ok(self):
        """获取用户标签-正向用例"""
        res = self.admin_kid.getKidTags(self.authorization, self.kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['kidId'] == str(self.kid_id), f"接口返回data数据异常：{res['data']}"
        assert res['data']['childAge'] == 0

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
    def test_admin_kid_permission_getKidTags(self, desc, value):
        """获取用户标签-权限测试"""
        res = self.admin_kid.getKidTags(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_admin_kid_positive_update_ok(self):
        """更新用户标签-正向用例"""
        res = self.admin_kid.updateKidTags(self.authorization, self.kid_id, learningLevel='L2')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == True, f"接口返回data数据异常：{res['data']}"

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
    def test_admin_kid_permission_updateKidTags(self, desc, value):
        """更新用户标签-权限测试"""
        res = self.admin_kid.updateKidTags(value, 0, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
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

    @pytest.mark.smoke
    def test_admin_kid_positive_updateSkillMastery_ok(self, getSecondekidId):
        """更新用户技能标签-正向用例"""
        kid_id = getSecondekidId
        skillMasteryMap = self.admin_kid.getSkillMastery(self.authorization, kid_id)['data']['skillMasteryMap']
        for k, v in skillMasteryMap.items():
            if k == 'Letter Recognition-L2':
                pl = {
                    "kidId": kid_id,
                    "skill": v['skill'],
                    "masteryScore": 74.0,
                    "masteryState": "Practicing"
                }
        res = self.admin_kid.updateSkillMastery(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.fixture(scope="class")
    def kid_data_fixture(self):
        '''创建测试学生'''
        # 创建测试学生
        kid_name = 'dibo_test_kid' + self.now
        kid_id = self.user.createkid(self.authorization, kid_name)['data']['id']
        yield kid_id
        # 删除测试学生
        self.user.deletekid(self.authorization, kid_id)

    @pytest.mark.release
    def test_adminKid_tagChangeLogs_changeItem_learningLevel(self, kid_data_fixture):
        """获取孩子等级状态操作日志-校验孩子学习状态更改项"""
        # 创建测试学生
        kid_id = kid_data_fixture
        # 更新用户标签前，获取孩子等级状态操作日志，验证当前无Learning Level相关日志
        res = self.admin_kid.tagChangeLogs(self.authorization, kid_id, changeItem='Learning Level')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        logs_before = res['data']['content']
        assert not logs_before
        # 更新用户标签，learningLevel更改为L2
        res = self.admin_kid.updateKidTags(self.authorization, kid_id, learningLevel='L2')
        assert res['message'] == 'success'
        # 更新用户标签后，获取孩子等级状态操作日志，验证changeItems字段筛选日志成功
        res = self.admin_kid.tagChangeLogs(self.authorization, kid_id, changeItem='Learning Level')
        logs_after = res['data']['content']
        operator = self.admin_kid.get_user_account()[1][0]
        assert len(logs_after) == 1
        assert logs_after[0]['kidId'] == kid_id
        assert logs_after[0]['operator'] == operator
        assert logs_after[0]['operatorSource'] == 'Admin'
        assert logs_after[0]['changeItem'] == 'Learning Level'
        assert logs_after[0]['oldValue'] == 'L1'
        assert logs_after[0]['newValue'] == 'L2'
        # 更新用户标签后，获取孩子等级状态操作日志，验证operator字段筛选日志成功
        operator = self.admin_kid.get_user_account()[1][0]
        res = self.admin_kid.tagChangeLogs(self.authorization, kid_id,  operator=operator)
        logs_after = res['data']['content']
        assert len(logs_after) == 1
        assert logs_after[0]['kidId'] == kid_id
        assert logs_after[0]['operator'] == operator
        assert logs_after[0]['operatorSource'] == 'Admin'
        assert logs_after[0]['changeItem'] == 'Learning Level'
        assert logs_after[0]['oldValue'] == 'L1'
        assert logs_after[0]['newValue'] == 'L2'
        # 更新用户标签后，获取孩子等级状态操作日志，验证operatorSource字段筛选日志成功
        res = self.admin_kid.tagChangeLogs(self.authorization, kid_id,  operatorSource='Admin')
        logs_after = res['data']['content']
        assert len(logs_after) == 1
        assert logs_after[0]['kidId'] == kid_id
        assert logs_after[0]['operator'] == operator
        assert logs_after[0]['operatorSource'] == 'Admin'
        assert logs_after[0]['changeItem'] == 'Learning Level'
        assert logs_after[0]['oldValue'] == 'L1'
        assert logs_after[0]['newValue'] == 'L2'
        # 更新用户标签后，获取孩子等级状态操作日志，验证默认条件筛选日志成功
        res = self.admin_kid.tagChangeLogs(self.authorization, kid_id)
        logs_after = res['data']['content']
        assert len(logs_after) == 1
        assert logs_after[0]['kidId'] == kid_id
        assert logs_after[0]['operator'] == operator
        assert logs_after[0]['operatorSource'] == 'Admin'
        assert logs_after[0]['changeItem'] == 'Learning Level'
        assert logs_after[0]['oldValue'] == 'L1'
        assert logs_after[0]['newValue'] == 'L2'

    @pytest.mark.release
    def test_adminKid_tagChangeLogs_changeItem_childAge(self, kid_data_fixture):
        """获取孩子等级状态操作日志-校验孩子学习状态更改项"""
        # 创建测试学生
        kid_id = kid_data_fixture
        # 更新用户标签前，获取孩子等级状态操作日志，验证当前无Learning Level相关日志
        res = self.admin_kid.tagChangeLogs(self.authorization, kid_id, changeItem='Child Age')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        logs_before = res['data']['content']
        assert not logs_before
        # 更新用户标签，learningLevel更改为L2
        res = self.admin_kid.updateKidTags(self.authorization, kid_id, childAge=8)
        assert res['message'] == 'success'
        # 更新用户标签后，获取孩子等级状态操作日志，验证当前LearningLevel相关日志信息正确
        res = self.admin_kid.tagChangeLogs(self.authorization, kid_id, changeItem='Child Age')
        logs_after = res['data']['content']
        operator = self.admin_kid.get_user_account()[1][0]
        assert len(logs_after) == 1
        assert logs_after[0]['kidId'] == kid_id
        assert logs_after[0]['operator'] == operator
        assert logs_after[0]['operatorSource'] == 'Admin'
        assert logs_after[0]['changeItem'] == 'Child Age'
        assert int(logs_after[0]['oldValue']) == 7
        assert int(logs_after[0]['newValue']) == 8

    @pytest.mark.release
    def test_adminKid_tagChangeLogs_changeItem_skillMastery(self, kid_data_fixture):
        """获取孩子等级状态操作日志-校验孩子学习状态更改项"""
        # 创建测试学生
        kid_id = kid_data_fixture
        # 更新用户标签前，获取孩子等级状态操作日志，验证当前无Learning Level相关日志
        res = self.admin_kid.tagChangeLogs(self.authorization, kid_id, changeItem='Skill Mastery')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        logs_before = res['data']['content']
        assert not logs_before

        # 回答课后quiz创建Skill Mastery数据
        # Normal课程资源列表
        course_id = self.school.getNormalcourse(self.authorization)["data"]['content'][0]['id']
        # 根据题库获取Quiz题目
        pl = {
            "count": 1,
            "kidId": kid_id,
            "levelList": ['L1']
        }
        question_res = self.quiz.fetchQuestions(self.authorization, **pl)['data']['data'][0]
        quizId = question_res['quizId']
        questions = question_res['questions']

        answers = []
        for question in questions:
            assert question['difficulty'] == 'L1'
            questionContent = json.loads(question['questionContent'])
            answers.append(
                {
                    "quizId": quizId,
                    "questionId": question['id'],
                    "questionSeqNo": 0,
                    "question": questionContent['question'],
                    "userAnswer": 'yes',
                    "correctAnswer": 'yes',
                    "isCorrect": True,
                    "skillTags": [question['skill']],
                    "completeTimeStamp": 0
                }
            )
        # 提交课后Quiz
        lesson_res = self.quiz.lessonSubmit(self.authorization, kid_id, course_id, answers)
        assert lesson_res['message'] == 'success'

        # 更新用户标签后，获取孩子等级状态操作日志，验证当前changeItem相关日志信息正确
        res = self.admin_kid.tagChangeLogs(self.authorization, kid_id, changeItem='Skill Mastery')
        logs_after = res['data']['content']
        assert len(logs_after)
        for log in logs_after:
            assert log['kidId'] == kid_id
            assert log['operator'] == 'System'
            assert log['operatorSource'] == 'System'
            assert logs_after[0]['changeItem'] == 'Skill Mastery'
            assert log['changePath'].startswith('SkillMastery.') and log['changePath'].endswith('-L1.Score') or log['changePath'].startswith('SkillMastery.') and log['changePath'].endswith('-L1.State') or log['changePath'].startswith('SkillMastery.') and log['changePath'].endswith('-L1.Components')
            if log['changePath'].endswith('-L1.Score'):
                assert log['oldValue'] == '0.00'
                assert log['newValue'] == '20.00'
            elif log['changePath'].endswith('-L1.State'):
                assert log['oldValue'] == 'Untouched'
                assert log['newValue'] == 'Weak'
            else:
                assert not log['oldValue']
                assert log['newValue'] == question['skill']
        # 更新用户标签后，获取孩子等级状态操作日志，验证operator字段筛选日志成功
        res = self.admin_kid.tagChangeLogs(self.authorization, kid_id, operator='System')
        logs_after = res['data']['content']
        assert len(logs_after)
        for log in logs_after:
            assert log['kidId'] == kid_id
            assert log['operator'] == 'System'
            assert log['operatorSource'] == 'System'
            assert logs_after[0]['changeItem'] == 'Skill Mastery'
            assert log['changePath'].startswith('SkillMastery.Letter-') and log['changePath'].endswith('-L1.Score') or log['changePath'].startswith('SkillMastery.Letter-') and log['changePath'].endswith('-L1.State') or log['changePath'].startswith('SkillMastery.Letter-') and log['changePath'].endswith('-L1.Components')
            if log['changePath'].endswith('-L1.Score'):
                assert log['oldValue'] == '0.00'
                assert log['newValue'] == '20.00'
            elif log['changePath'].endswith('-L1.State'):
                assert log['oldValue'] == 'Untouched'
                assert log['newValue'] == 'Weak'
            else:
                assert not log['oldValue']
                assert log['newValue'] == question['skill']
        # 更新用户标签后，获取孩子等级状态操作日志，验证operatorSource字段筛选日志成功
        res = self.admin_kid.tagChangeLogs(self.authorization, kid_id, operatorSource='System')
        logs_after = res['data']['content']
        assert len(logs_after)
        for log in logs_after:
            assert log['kidId'] == kid_id
            assert log['operator'] == 'System'
            assert log['operatorSource'] == 'System'
            assert logs_after[0]['changeItem'] == 'Skill Mastery'
            assert log['changePath'].startswith('SkillMastery.Letter-') and log['changePath'].endswith('-L1.Score') or log['changePath'].startswith('SkillMastery.Letter-') and log['changePath'].endswith('-L1.State') or log['changePath'].startswith('SkillMastery.Letter-') and log['changePath'].endswith('-L1.Components')
            if log['changePath'].endswith('-L1.Score'):
                assert log['oldValue'] == '0.00'
                assert log['newValue'] == '20.00'
            elif log['changePath'].endswith('-L1.State'):
                assert log['oldValue'] == 'Untouched'
                assert log['newValue'] == 'Weak'
            else:
                assert not log['oldValue']
                assert log['newValue'] == question['skill']
        # 更新用户标签后，获取孩子等级状态操作日志，验证默认条件筛选日志成功
        res = self.admin_kid.tagChangeLogs(self.authorization, kid_id)
        logs_after = res['data']['content']
        assert len(logs_after)
        for log in logs_after:
            assert log['kidId'] == kid_id
            assert log['operator'] == 'System'
            assert log['operatorSource'] == 'System'
            assert logs_after[0]['changeItem'] == 'Skill Mastery'
            assert log['changePath'].startswith('SkillMastery.Letter-') and log['changePath'].endswith('-L1.Score') or log['changePath'].startswith('SkillMastery.Letter-') and log['changePath'].endswith('-L1.State') or log['changePath'].startswith('SkillMastery.Letter-') and log['changePath'].endswith('-L1.Components')
            if log['changePath'].endswith('-L1.Score'):
                assert log['oldValue'] == '0.00'
                assert log['newValue'] == '20.00'
            elif log['changePath'].endswith('-L1.State'):
                assert log['oldValue'] == 'Untouched'
                assert log['newValue'] == 'Weak'
            else:
                assert not log['oldValue']
                assert log['newValue'] == question['skill']

    @pytest.mark.release
    def test_admin_kid_all_skillEventPublish_ok(self, kid_data_fixture):
        """手动发布技能事件-验证批量触发技能事件，学生技能分数增加"""
        # 创建测试学生
        kid_id = kid_data_fixture
        # 手动发布技能事件前，获取学生技能掌握程度，验证新增学生无技能数据
        skillMastery1 = self.admin_kid.getSkillMastery(self.authorization, kid_id)['data']
        assert not skillMastery1['skillMasteryMap']
        # 手动发布技能事件前，分页查询课程等级技能列表，验证新增学生无技能数据
        skills_res = self.admin_levelskills.level_skills(self.authorization)['data']
        skills = list(set(DataFrame(skills_res)['skill'].tolist()))
        # 手动批量发布技能事件
        res = self.admin_kid.skillEventPublish(self.authorization, kid_id, skills, 85.2)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == True, f"接口返回data数据异常：{res['data']}"
        time.sleep(2)   # /admin/kid/skill-event/publish 只是把事件丢到 MQ（topic skill_mastery_update），由消费者异步更新技能表/缓存
        for i in range(20):
            # 手动发布技能事件后，获取学生技能掌握程度，手动批量发布技能事件后台处理后，学生技能增加
            skillMastery2 = self.admin_kid.getSkillMastery(self.authorization, kid_id)['data']
            if skillMastery2['skillMasteryMap']:
                for k, v in skillMastery2['skillMasteryMap'].items():
                    assert k in skills
                    assert v['skill'] in skills
                    if not v['components']['allComponents']:
                        assert v['masteryScore'] == 17.04
                        assert v['masteryState'] == 'Weak'
                        assert v['componentExposureRate'] == 1.0
                    else:
                        pass
                break
            else:
                time.sleep(1)
        else:
            assert False, "12s消费者异步更新技能表/缓存未成功！"

    @pytest.mark.release
    def test_admin_kid_skill_skillEventPublish_check(self, kid_data_fixture):
        """手动发布技能事件-验证无子技能的技能标签学习分数正常增加"""
        # 创建测试学生
        kid_id = kid_data_fixture
        # 手动发布技能事件前，获取学生技能掌握程度，验证新增学生无技能数据
        skillMastery1 = self.admin_kid.getSkillMastery(self.authorization, kid_id)['data']
        assert not skillMastery1['skillMasteryMap']
        # 手动发布技能事件前，分页查询课程等级技能列表，选择无子技能的技能标签进行测试
        skills_res = self.admin_levelskills.level_skills(self.authorization)['data']
        for skill in skills_res:
            if not skill['parentSkill']:
                skills = [skill['skill']]
                break
        actual_score = 0
        for i in range(10):
            # 手动发布技能事件
            random_score = round(random.uniform(0, 100), 2)
            res = self.admin_kid.skillEventPublish(self.authorization, kid_id, skills, random_score)
            assert res['message'] == 'success'
            expected_score =  round(0.8 * actual_score + 0.2 * random_score, 2)
            if expected_score >= 100:
                expected_score = 100

            time.sleep(2)   # /admin/kid/skill-event/publish 只是把事件丢到 MQ（topic skill_mastery_update），由消费者异步更新技能表/缓存
            for i in range(20):
                # 手动发布技能事件后，获取学生技能掌握程度，手动批量发布技能事件后台处理后，学生技能增加
                skillMastery2 = self.admin_kid.getSkillMastery(self.authorization, kid_id)['data']
                if skillMastery2['skillMasteryMap']:
                    for k, v in skillMastery2['skillMasteryMap'].items():
                        if k == skills[0]:
                            assert v['componentExposureRate'] == 1.0
                            assert v['masteryScore'] == expected_score
                            if expected_score < 25:
                                assert v['masteryState'] == 'Weak'
                                actual_score = expected_score
                            elif 25 < expected_score <= 75:
                                assert v['masteryState'] == 'Practicing'
                                actual_score = expected_score
                            elif expected_score >= 75:
                                assert v['masteryState'] == 'Mastered'
                                actual_score = expected_score
                        break
                else:
                    time.sleep(1)
                if actual_score == expected_score:
                    break
            else:
                assert False, "12s消费者异步更新技能表/缓存未成功！"
            if expected_score == 100:
                break

    @pytest.mark.release
    def test_admin_kid_subSkill_skillEventPublish_full_check(self, kid_data_fixture):
        """手动发布技能事件-验证有子技能的技能标签学习分数正常增加（遍历5种子技能，且每种子技能得分100）"""
        # 创建测试学生
        kid_id = kid_data_fixture
        # 手动发布技能事件前，获取学生技能掌握程度，验证新增学生无技能数据
        skillMastery1 = self.admin_kid.getSkillMastery(self.authorization, kid_id)['data']
        assert not skillMastery1['skillMasteryMap']
        # 手动发布技能事件前，分页查询课程等级技能列表，选择有子技能的技能标签进行测试
        skills_res = self.admin_levelskills.level_skills(self.authorization)['data']
        sub_skills, parentSkill = [], ''
        for skill in skills_res:
            if skill['parentSkill'] and not parentSkill:
                parentSkill = skill['parentSkill']
                sub_skills.append(skill['skill'])
            elif skill['parentSkill'] == parentSkill:
                sub_skills.append(skill['skill'])
        actual_score = 0
        for sub_skill in sub_skills:
            random_score = 100.00
            # 手动发布技能事件
            res = self.admin_kid.skillEventPublish(self.authorization, kid_id, [sub_skill], random_score)
            assert res['message'] == 'success'
            expected_score =  round(0.8 * actual_score + 0.2 * random_score, 2)
            if expected_score >= 100:
                expected_score = 100

            time.sleep(2)   # /admin/kid/skill-event/publish 只是把事件丢到 MQ（topic skill_mastery_update），由消费者异步更新技能表/缓存
            for i in range(20):
                # 手动发布技能事件后，获取学生技能掌握程度，手动批量发布技能事件后台处理后，学生技能增加
                skillMastery2 = self.admin_kid.getSkillMastery(self.authorization, kid_id)['data']
                if skillMastery2['skillMasteryMap']:
                    for k, v in skillMastery2['skillMasteryMap'].items():
                        if k == parentSkill:
                            assert v['componentExposureRate'] == round(0.2 * (sub_skills.index(sub_skill)+1), 2)
                            assert v['masteryScore'] == expected_score
                            if expected_score < 25:
                                assert v['masteryState'] == 'Weak'
                                actual_score = expected_score
                            elif 25 < expected_score <= 75:
                                assert v['masteryState'] == 'Practicing'
                                actual_score = expected_score
                            elif expected_score >= 75:
                                assert v['masteryState'] == 'Mastered'
                                actual_score = expected_score
                        break
                else:
                    time.sleep(1)
                if actual_score == expected_score:
                    break
            else:
                assert False, "12s消费者异步更新技能表/缓存未成功！"
            if expected_score == 100:
                break

    @pytest.mark.release
    def test_admin_kid_subSkill_skillEventPublish_type_check(self, kid_data_fixture):
        """手动发布技能事件-验证有子技能的技能标签学习分数正常增加（随机子技能，随机得分）"""
        # 创建测试学生
        kid_id = kid_data_fixture
        # 手动发布技能事件前，获取学生技能掌握程度，验证新增学生无技能数据
        skillMastery1 = self.admin_kid.getSkillMastery(self.authorization, kid_id)['data']
        assert not skillMastery1['skillMasteryMap']
        # 手动发布技能事件前，分页查询课程等级技能列表，选择有子技能的技能标签进行测试
        skills_res = self.admin_levelskills.level_skills(self.authorization)['data']
        sub_skills, parentSkill = [], ''
        for skill in skills_res:
            if skill['parentSkill'] and not parentSkill:
                parentSkill = skill['parentSkill']
                sub_skills.append(skill['skill'])
            elif skill['parentSkill'] == parentSkill:
                sub_skills.append(skill['skill'])
        actual_score = 0
        for i in range(10):
            random_score = round(random.uniform(0, 100), 2)
            # 随机选择一种子技能
            choice_sub_skills = random.choice(sub_skills)
            skills = [choice_sub_skills]
            # 手动发布技能事件
            res = self.admin_kid.skillEventPublish(self.authorization, kid_id, skills, random_score)
            assert res['message'] == 'success'
            expected_score =  round(0.8 * actual_score + 0.2 * random_score, 2)
            if expected_score >= 100:
                expected_score = 100
            componentExposureRate = 0
            time.sleep(2)   # /admin/kid/skill-event/publish 只是把事件丢到 MQ（topic skill_mastery_update），由消费者异步更新技能表/缓存
            for j in range(20):
                # 手动发布技能事件后，获取学生技能掌握程度，手动批量发布技能事件后台处理后，学生技能增加
                skillMastery2 = self.admin_kid.getSkillMastery(self.authorization, kid_id)['data']
                if skillMastery2['skillMasteryMap']:
                    for k, v in skillMastery2['skillMasteryMap'].items():
                        if k == parentSkill:
                            exposedComponents = DataFrame(v['components']['exposedComponents'])['componentKey'].tolist()
                            if choice_sub_skills not in exposedComponents:
                                assert v['componentExposureRate'] == componentExposureRate + 0.2
                                componentExposureRate = v['componentExposureRate']
                            assert v['masteryScore'] == expected_score
                            if expected_score < 25:
                                assert v['masteryState'] == 'Weak'
                                actual_score = expected_score
                            elif 25 < expected_score <= 75:
                                assert v['masteryState'] == 'Practicing'
                                actual_score = expected_score
                            elif expected_score >= 75:
                                assert v['masteryState'] == 'Mastered'
                                actual_score = expected_score
                        break
                else:
                    time.sleep(1)
                if actual_score == expected_score:
                    break
            else:
                assert False, "12s消费者异步更新技能表/缓存未成功！"
            if expected_score == 100:
                break