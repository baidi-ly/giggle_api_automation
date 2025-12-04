import datetime

import pytest
import sys
import os

from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.game.game_api import GameApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.learning.learning_api import LearningApi
from test_case.page_api.reward.reward_api import RewardApi
from test_case.page_api.user.user_api import UserApi

sys.path.append(os.getcwd())
sys.path.append("..")


@pytest.mark.Learning
class TestLearning:

    def setup_class(self):
        self.learning = LearningApi()
        self.course = CourseApi()
        self.authorization = self.learning.get_authorization()[0]
        self.kid = KidApi()
        self.user = UserApi()
        self.game = GameApi()
        self.reward = RewardApi()

        self.today = datetime.date.today().strftime("%Y-%m-%d")
        self.yesterday = (datetime.date.today() - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        self.tomorrow = (datetime.date.today() + datetime.timedelta(days=1)).strftime("%Y-%m-%d")

        _today = datetime.date.today()  # 当前日期
        self.start_of_week = _today - datetime.timedelta(days=_today.weekday())  # 本周周一
        self.end_of_week = self.start_of_week + datetime.timedelta(days=6)  # 本周周日

        try:
            kids_res = self.kid.getKids(self.authorization)
            self.kid_name = 'New Kid'
            for kid in kids_res['data']:
                if kid['name'] == self.kid_name:
                    self.kid_id = kid['id']
                    break
        except Exception as e:
            print(f'获取孩子失败，原因是：{e}')

    @pytest.fixture(scope="class")
    def getkidId(self):
        '''类前置 - 获取kidId'''
        kidId = self.kid.getKids(self.authorization)
        yield kidId

    @pytest.fixture(scope="function")
    def create_deletedAccount(self):
        '''方法前置 - 创建kidId'''
        # 创建小孩账户
        kidId = self.kid.getKids(self.authorization)
        # 注销小孩账户
        yield kidId

    @pytest.mark.release
    def test_learning_stats_byKidId_normal(self):
        """获取孩子学习统计数据 - 校验数据正确性"""
        # 获取孩子学习统计数据
        stats_res = self.learning.learning_stats(self.kid_id, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]['childInfo']['childId'] == str(self.kid_id)
        assert stats_res["data"]['childInfo']['name'] == 'New Kid'
        assert stats_res["data"]['childInfo']['avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        # 查询晋级进度条，获取当前孩子的等级
        lp_res = self.kid.getLearningProgress(self.authorization, self.kid_id)
        learningLevel =  lp_res['data']['learningLevel'].split('L')[-1]
        actual_progress = stats_res["data"]['learningStats']['level']['progress']
        # 检查今天是否已经通过每日课程完成增加过抽奖次数
        status_res = self.game.learningStatusV2(self.authorization, self.kid_id)['data']
        learning_histories = status_res['learningHistories']
        if learning_histories:
            learned_course_ids = [history['lessonId'] for history in learning_histories]
            expected_lessons = len(set(learned_course_ids))
        else:
            expected_lessons = 0
        # 获取连续学习进度
        expected_streak = self.reward.continuousProgress(self.authorization, self.kid_id)['data']['days']
        # 校验孩子学习统计数据准确性
        assert stats_res["data"]['learningStats']['lessonsCompleted'] == expected_lessons
        assert 'booksRead' in stats_res["data"]['learningStats']
        assert stats_res["data"]['learningStats']['currentStreak'] == expected_streak
        assert stats_res["data"]['learningStats']['level']['currentLevel'] == int(learningLevel)
        assert stats_res["data"]['learningStats']['level']['levelName'] == f'level-{learningLevel}'
        assert actual_progress


    def test_learning_stats_byKidId_deletedAccount(self, create_deletedAccount):
        """注销的kidId，返回错误信息"""
        # 获取有效的kidId
        kidId = create_deletedAccount
        # 获取孩子学习统计数据
        stats_res = self.learning.learning_stats(self.kid_id, self.authorization)
        assert "msg" in stats_res, f"获取孩子学习统计数据接口没有msg数据，response->{stats_res}"
        assert stats_res["msg"] == "无效的kidId", f'无效的kidId返回错误信息有误，预期:无效的kidId, 实际：{stats_res["msg"]}'

    def test_learning_stats_byKidId_invalid(self):
        """无效的kidId - 返回错误信息"""
        # 创建无效的kidId
        kidId = 9999999
        # 获取孩子学习统计数据
        stats_res = self.learning.learning_stats(self.kid_id, self.authorization, code=500)
        assert stats_res["code"] == 500, f'无效的kidId返回状态码不正确，预期:500, 实际：{stats_res["code"]}'
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有msg数据，response->{stats_res}"
        assert stats_res["data"]["message"] == f"孩子不存在: {kidId}", f'无效的kidId返回错误信息有误，预期:无效的kidId, 实际：{stats_res["data"]}'

    def test_learning_stats_byKidId_unauthorized(self):
        """有效的kidId - 未授权，返回401"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 未授权，获取孩子学习统计数据
        self.learning.learning_stats(self.kid_id, code=401)

    def test_learning_stats_byKidId_negative(self):
        """kidId为负数 - 返回错误信息"""
        # 创建负数kidId
        kidId = -1
        # 获取孩子学习统计数据
        stats_res = self.learning.learning_stats(self.kid_id, self.authorization, code=500)
        assert "message" in stats_res, f"获取孩子学习统计数据接口没有msg数据，response->{stats_res}"
        assert stats_res["message"] == "internal server error", (f'kidId为负数返回错误信息有误，'
                                                                 f'预期:internal server error, 实际：{stats_res["message"]}')

    @pytest.mark.release
    def test_learning_daily_byKidId_normal(self):
        """获取孩子今日学习详情，有数据的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        daily_res = self.learning.daily_learning(self.kid_id, self.authorization)
        today = datetime.date.today().strftime("%Y-%m-%d")
        assert daily_res['data']['date'] == today
        assert daily_res['data']['courses']
        assert daily_res['data']['storybooks']
        assert daily_res['data']['flashcard']
        # assert daily_res['data']['myWorks']

    def test_learning_daily_byKidId_normal_empty(self):
        """获取孩子今日学习详情，无数据的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        daily_res = self.learning.daily_learning('', self.authorization, code=404)
        assert daily_res['error'] == 'Not Found', f"获取孩子今日学习详情接口没有data数据，response->{daily_res}"
        assert daily_res['status'] == 404, f"获取孩子今日学习详情接口没有data数据，response->{daily_res}"

    def test_learning_daily_byKidId_special_character(self):
        """获取孩子今日学习详情，无效的kidId - 返回错误信息"""
        # 创建无效的kidId
        kidId = '@@#$%^&*'
        # 获取孩子学习统计数据
        daily_res = self.learning.daily_learning(self.kid_id, self.authorization, code=400)
        error_msg = "获取孩子今日学习详情-无效的kidId"
        assert daily_res['message'] == 'invalid parameter', f'{error_msg}-返回状态码不正确，预期:500, 实际：{daily_res["code"]}'
        assert daily_res['data'] == '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: "@@"''', f'{error_msg}-返回状态码不正确，预期:500, 实际：{daily_res["code"]}'

    def test_learning_daily_byKidId_positive(self):
        """获取孩子今日学习详情，无效的kidId - 返回错误信息"""
        # 创建无效的kidId
        kidId = -9999
        # 获取孩子学习统计数据
        daily_res = self.learning.daily_learning(self.kid_id, self.authorization, code=500)
        error_msg = "获取孩子今日学习详情-无效的kidId"
        assert daily_res['message'] == 'internal server error', f'{error_msg}-返回状态码不正确，预期:500, 实际：{daily_res["code"]}'

    def test_learning_daily_byKidId_negative(self):
        """kidId为负数 - 返回错误信息"""
        # 创建负数kidId
        kidId = -1
        # 获取孩子学习统计数据
        daily_res = self.learning.daily_learning(self.kid_id, self.authorization, code=500)
        assert "message" in daily_res, f"获取孩子学习统计数据接口没有msg数据，response->{daily_res}"
        assert daily_res["message"] == "internal server error", (f'kidId为负数返回错误信息有误，'                                     
                                                                 f'预期:internal server error, 实际：{daily_res["message"]}')

    @pytest.mark.release
    def test_learning_daily_learning_report_ok(self):
        """生成指定孩子的学习情况报表数据，生成今日报表"""
        # 获取孩子学习统计数据
        report_res = self.learning.daily_learning_report(self.kid_id, authorization=self.authorization)
        assert "data" in report_res, f"获取孩子学习统计数据接口没有data数据，response->{report_res}"
        assert report_res["data"]["date"] == self.today
        assert report_res["data"]['childInfo']['childId'] == str(self.kid_id)
        assert report_res["data"]['childInfo']['name'] == 'New Kid'
        assert report_res["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert report_res["data"]['summary']
        assert report_res["data"]['learningSummary']
        assert report_res["data"]['wordsLearned']
        assert report_res["data"]['artworks']

    @pytest.mark.release
    def test_learning_daily_learning_report_yesterday(self):
        """生成指定孩子的学习情况报表数据，生成今日报表"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        report_res = self.learning.daily_learning_report(self.kid_id, authorization=self.authorization, date=self.yesterday)
        assert report_res["data"]["date"] == self.today
        assert report_res["data"]['childInfo']['childId'] == str(self.kid_id)
        assert report_res["data"]['childInfo']['name'] == 'New Kid'
        assert report_res["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert report_res["data"]['summary']
        assert report_res["data"]['learningSummary']
        assert report_res["data"]['wordsLearned']
        assert report_res["data"]['artworks']

    @pytest.mark.release
    def test_learning_daily_learning_report_tomorrow(self):
        """生成指定孩子的学习情况报表数据，生成今日报表"""
        # 获取孩子学习统计数据
        report_res = self.learning.daily_learning_report(self.kid_id, authorization=self.authorization, date=self.tomorrow)
        assert report_res["data"]["date"] == self.today
        assert report_res["data"]['childInfo']['childId'] == str(self.kid_id)
        assert report_res["data"]['childInfo']['name'] == 'New Kid'
        assert report_res["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert report_res["data"]['summary']
        assert report_res["data"]['learningSummary']
        assert report_res["data"]['wordsLearned']
        assert report_res["data"]['artworks']

    @pytest.mark.release
    def test_learning_weekly_byKidId_thisWeekend(self):
        """获取本周学习"""
        # 获取孩子学习统计数据
        startDate = self.start_of_week
        endDate = self.end_of_week
        weekly_learning_res = self.learning.weekly_learning(self.authorization, self.kid_id, startDate, endDate)
        assert weekly_learning_res["weekPeriod"] == str(self.start_of_week) + ' - ' + str(self.end_of_week)
        return_keys = ["courses", 'storybooks', 'flashcard', 'myWorks']
        for for_key in return_keys:
            assert for_key in weekly_learning_res, f"获取孩子学习统计数据接口没有data数据，response->{weekly_learning_res}"

    @pytest.mark.release
    def test_learning_weekly_byKidId_nextWeekend(self):
        """跨周测试 - 下一周"""
        # 获取孩子学习统计数
        startDate = self.start_of_week.strftime("%Y-%m-%d")
        endDate = self.end_of_week.strftime("%Y-%m-%d")
        weekly_learning_res = self.learning.weekly_learning(self.authorization, self.kid_id, startDate, endDate)
        assert weekly_learning_res["weekPeriod"] == str(self.start_of_week) + ' - ' + str(self.end_of_week)
        assert weekly_learning_res['courses']
        assert weekly_learning_res['storybooks']
        assert weekly_learning_res['flashcard']
        # assert weekly_learning_res['myWorks']

    @pytest.mark.release
    def test_learning_weekly_byKidId_lastWeekend(self):
        """跨周测试 - 上一周"""
        # 获取孩子学习统计数据
        startDate = self.start_of_week
        endDate = self.end_of_week
        weekly_learning_res = self.learning.weekly_learning(self.authorization, self.kid_id, startDate, endDate)
        assert weekly_learning_res["weekPeriod"] == str(self.start_of_week) + ' - ' + str(self.end_of_week)
        assert weekly_learning_res['courses']
        assert weekly_learning_res['storybooks']
        assert weekly_learning_res['flashcard']
        # assert weekly_learning_res['myWorks']

    @pytest.mark.release
    def test_learning_weekly_learning_report_targetWeekend(self):
        """跨周测试 - 上一周"""
        # 获取孩子学习统计数据
        startDate = "2025-01-20"
        endDate = "2025-01-26"
        weekly_learning_res = self.learning.weekly_learning(self.authorization, self.kid_id, startDate, endDate)
        assert weekly_learning_res["weekPeriod"] == str(self.start_of_week) + ' - ' + str(self.end_of_week)
        assert weekly_learning_res['courses']
        assert weekly_learning_res['storybooks']
        assert weekly_learning_res['flashcard']
        # assert weekly_learning_res['myWorks']


    @pytest.mark.release
    def test_learning_daily_storybook_report_target(self):
        """生成今日故事书报告"""
        # 获取孩子学习统计数据
        date = "2025-01-20"
        torybook_report = self.learning.daily_storybook_report(self.kid_id, date, self.authorization)
        assert torybook_report["data"]["date"] == date
        assert torybook_report["data"]['childInfo']['childId'] == str(self.kid_id)
        assert torybook_report["data"]['childInfo']['name'] == 'New Kid'
        assert torybook_report["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert torybook_report["data"]['summary']
        assert torybook_report["data"]['aiSummary']
        assert torybook_report["data"]['durationComparison']
        assert torybook_report["data"]['theme']
        assert torybook_report["data"]['storybooks']

    def test_learning_daily_storybook_report_today(self):
        """无故事书阅读记录"""
        # 获取孩子学习统计数据
        torybook_report = self.learning.daily_storybook_report(self.kid_id, self.today, self.authorization)
        assert torybook_report["data"]["date"] == self.today
        assert torybook_report["data"]['childInfo']['childId'] == str(self.kid_id)
        assert torybook_report["data"]['childInfo']['name'] == 'New Kid'
        assert torybook_report["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert torybook_report["data"]['summary']
        assert torybook_report["data"]['aiSummary']
        assert torybook_report["data"]['durationComparison']
        assert torybook_report["data"]['theme']
        assert torybook_report["data"]['storybooks']

    def test_learning_daily_storybook_report_tomorrow(self):
        """无故事书阅读记录"""
        # 获取孩子学习统计数据
        torybook_report = self.learning.daily_storybook_report(self.kid_id, self.tomorrow, self.authorization)
        assert torybook_report["data"]["date"] == self.tomorrow
        assert torybook_report["data"]['childInfo']['childId'] == str(self.kid_id)
        assert torybook_report["data"]['childInfo']['name'] == 'New Kid'
        assert torybook_report["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert torybook_report["data"]['summary']
        assert torybook_report["data"]['aiSummary']
        assert torybook_report["data"]['durationComparison']
        assert torybook_report["data"]['theme']
        assert torybook_report["data"]['storybooks']

    def test_learning_daily_storybook_report_yesterday(self):
        """无故事书阅读记录"""
        # 获取孩子学习统计数据
        torybook_report = self.learning.daily_storybook_report(self.kid_id, self.yesterday, self.authorization)
        assert torybook_report["data"]["date"] == self.yesterday
        assert torybook_report["data"]['childInfo']['childId'] == str(self.kid_id)
        assert torybook_report["data"]['childInfo']['name'] == 'New Kid'
        assert torybook_report["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert torybook_report["data"]['summary']
        assert torybook_report["data"]['aiSummary']
        assert torybook_report["data"]['durationComparison']
        assert torybook_report["data"]['theme']
        assert torybook_report["data"]['storybooks']



    def test_learning_daily_challenge_report_target(self):
        """生成今日故事书报告"""
        # 获取孩子学习统计数据
        date = "2025-01-20"
        challenge_res = self.learning.daily_challenge_report(self.kid_id, date, self.authorization)
        assert challenge_res["data"]["date"] == date
        assert challenge_res["data"]['childInfo']['childId'] == str(self.kid_id)
        assert challenge_res["data"]['childInfo']['name'] == 'New Kid'
        assert challenge_res["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert challenge_res["data"]['summary']
        assert challenge_res["data"]['aiSummary']
        assert challenge_res["data"]['words']
        assert challenge_res["data"]['animalCards']

    def test_learning_daily_challenge_report_today(self):
        """无故事书阅读记录"""
        # 获取孩子学习统计数据
        challenge_res = self.learning.daily_challenge_report(self.kid_id, self.today, self.authorization)
        assert challenge_res["data"]["date"] == self.today
        assert challenge_res["data"]['childInfo']['childId'] == str(self.kid_id)
        assert challenge_res["data"]['childInfo']['name'] == 'New Kid'
        assert challenge_res["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert challenge_res["data"]['summary']
        assert challenge_res["data"]['aiSummary']
        assert challenge_res["data"]['words']
        assert challenge_res["data"]['animalCards']

    def test_learning_daily_challenge_report_tomorrow(self):
        """无故事书阅读记录"""
        # 获取孩子学习统计数据
        challenge_res = self.learning.daily_challenge_report(self.kid_id, self.tomorrow, self.authorization)
        assert challenge_res["data"]["date"] == self.tomorrow
        assert challenge_res["data"]['childInfo']['childId'] == str(self.kid_id)
        assert challenge_res["data"]['childInfo']['name'] == 'New Kid'
        assert challenge_res["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert challenge_res["data"]['summary']
        assert challenge_res["data"]['aiSummary']
        assert challenge_res["data"]['words']
        assert challenge_res["data"]['animalCards']

    def test_learning_daily_challenge_report_yesterday(self):
        """无故事书阅读记录"""
        # 获取孩子学习统计数据
        challenge_res = self.learning.daily_challenge_report(self.kid_id, self.yesterday, self.authorization)
        assert challenge_res["data"]["date"] == self.yesterday
        assert challenge_res["data"]['childInfo']['childId'] == str(self.kid_id)
        assert challenge_res["data"]['childInfo']['name'] == 'New Kid'
        assert challenge_res["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert challenge_res["data"]['summary']
        assert challenge_res["data"]['aiSummary']
        assert challenge_res["data"]['words']
        assert challenge_res["data"]['animalCards']



    def test_learning_daily_flashcard_report_target(self):
        """生成今日故事书报告"""
        # 获取孩子学习统计数据
        date = "2025-01-20"
        flashcard_res = self.learning.daily_flashcard_report(self.kid_id, date, self.authorization)
        assert flashcard_res["data"]["date"] == date
        assert flashcard_res["data"]['childInfo']['childId'] == str(self.kid_id)
        assert flashcard_res["data"]['childInfo']['name'] == 'New Kid'
        assert flashcard_res["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert flashcard_res["data"]['summary']
        assert flashcard_res["data"]['aiSummary']
        assert flashcard_res["data"]['words']
        assert flashcard_res["data"]['themeCompletion']
        assert flashcard_res["data"]['animalCards']

    def test_learning_daily_flashcard_report_today(self):
        """无故事书阅读记录"""
        # 获取孩子学习统计数据
        flashcard_res = self.learning.daily_flashcard_report(self.kid_id, self.today, self.authorization)
        assert flashcard_res["data"]["date"] == self.today
        assert flashcard_res["data"]['childInfo']['childId'] == str(self.kid_id)
        assert flashcard_res["data"]['childInfo']['name'] == 'New Kid'
        assert flashcard_res["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert flashcard_res["data"]['summary']
        assert flashcard_res["data"]['aiSummary']
        assert flashcard_res["data"]['words']
        assert flashcard_res["data"]['themeCompletion']
        assert flashcard_res["data"]['animalCards']

    def test_learning_daily_flashcard_report_tomorrow(self):
        """无故事书阅读记录"""
        # 获取孩子学习统计数据
        flashcard_res = self.learning.daily_flashcard_report(self.kid_id, self.tomorrow, self.authorization)
        assert flashcard_res["data"]["date"] == self.tomorrow
        assert flashcard_res["data"]['childInfo']['childId'] == str(self.kid_id)
        assert flashcard_res["data"]['childInfo']['name'] == 'New Kid'
        assert flashcard_res["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert flashcard_res["data"]['summary']
        assert flashcard_res["data"]['aiSummary']
        assert flashcard_res["data"]['words']
        assert flashcard_res["data"]['themeCompletion']
        assert flashcard_res["data"]['animalCards']

    def test_learning_daily_flashcard_report_yesterday(self):
        """无故事书阅读记录"""
        # 获取孩子学习统计数据
        flashcard_res = self.learning.daily_flashcard_report(self.kid_id, self.yesterday, self.authorization)
        assert flashcard_res["data"]["date"] == self.yesterday
        assert flashcard_res["data"]['childInfo']['childId'] == str(self.kid_id)
        assert flashcard_res["data"]['childInfo']['name'] == 'New Kid'
        assert flashcard_res["data"]['childInfo'][
                   'avatar'] == 'http://static.giggleacademy.com/admin/materials/653454754111557/17e678e7-08f8-4089-be25-975ca5d02e60.png'
        assert flashcard_res["data"]['summary']
        assert flashcard_res["data"]['aiSummary']
        assert flashcard_res["data"]['words']
        assert flashcard_res["data"]['themeCompletion']
        assert flashcard_res["data"]['animalCards']

    def test_interaction_event_single(self, get_couerseList):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        couerseList = get_couerseList[0]['courseList']
        eventName = "交互事件" + self.now
        courses = [
            {
                "eventName": eventName,
                "params": {
                    "courseId": couerseList[0]["id"],
                    "lessonType": "normal"
                }
             }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"