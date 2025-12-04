import datetime
import time

import pytest
import sys
import os

from pandas import DataFrame

from test_case.page_api.admin.admin_course_api import AdminCourseApi
from test_case.page_api.book.book_api import BookApi
from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.flash_cards.flash_cards_api import Flash_cardsApi
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
        self.authorization, self.user_id = self.learning.get_authorization()
        self.kid = KidApi()
        self.user = UserApi()
        self.game = GameApi()
        self.reward = RewardApi()
        self.book = BookApi()
        self.flashcard = Flash_cardsApi()

        self.admin_course = AdminCourseApi()
        self.admin_auth = self.admin_course.get_admin_authorization()[0]

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

    @pytest.fixture(scope='function')
    def get_courseIds(self):
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
                    courseIds = ','.join(DataFrame(courselistAll)[:3]['id'].tolist())
                    return courseIds

    @pytest.fixture(scope="class")
    def get_bookIds(self):
        '''方法前置 - 获取bookid'''
        book_res = self.book.book_list(self.authorization)['data']['content']
        bookIds = DataFrame(book_res)['id'].tolist()
        yield bookIds

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
        assert daily_res['data']['flash_cards']
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
        return_keys = ["courses", 'storybooks', 'flash_cards', 'myWorks']
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
        assert weekly_learning_res['flash_cards']
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
        assert weekly_learning_res['flash_cards']
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
        assert weekly_learning_res['flash_cards']
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

    def test_interaction_lesson_event_InteractiveLessonStart(self, get_courseIds):
        """上报用户交互事件 - 课程事件 - InteractiveLessonStart"""
        # 上报用户交互事件
        course_id = get_courseIds[0]
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "InteractiveLessonStart",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "lesson_id": course_id,
                    "from_page": "home_recommend"
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_lesson_event_InteractiveLessonEnd(self, get_courseIds):
        """上报用户交互事件 - 课程事件 - InteractiveLessonEnd"""
        # 上报事件前，获取孩子今日学习详情
        learning_res1 = self.learning.daily_learning(self.authorization, self.kid_id)
        l_duration1 = learning_res1["data"]['courses']['normal']["duration"]
        l_interaction1 = learning_res1["data"]['courses']['normal']["interaction"]
        # 上报事件前，生成指定孩子的学习情况报表数据
        report_res1 = self.learning.daily_learning_report(self.authorization, self.kid_id, self.today)
        r_interaction1 = report_res1["data"]['summary']['stats']["interaction"]
        r_duration1 = report_res1["data"]['summary']['stats']["duration"]
        # 上报用户交互事件
        course_id = get_courseIds.split(',')[0]
        timestamp_milliseconds1 = int(time.time() * 1000) - 1000
        timestamp_milliseconds2 = int(time.time() * 1000)
        timestamp_milliseconds3 = int(time.time() * 1000) + 1000
        courses = [
            {
                "eventName": "InteractiveLessonStart",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds1,
                    "lesson_id": course_id,
                    "from_page": "home_recommend"
                }
            },
            {
                "eventName": "LessonUserInteraction",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds2,
                    "lesson_id": course_id,
                    "interaction_type": "tap",
                    "component_key": "scene_1_q1"
                }
            },
            {
                "eventName": "InteractiveLessonEnd",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds3,
                    "lesson_id": course_id,
                    "duration": 360
                }
            }
        ]
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"
        assert event_res['data']['recordedCount'] == 3, f"接口返回data数据异常：{event_res['data']}"
        for i in range(10):
            try:
                # 上报事件后，获取孩子今日学习详情
                learning_res2 = self.learning.daily_learning(self.authorization, self.kid_id)
                l_duration2 = learning_res2["data"]['courses']['normal']["duration"]
                assert l_duration2 - l_duration1 == 6
                l_interaction2 = learning_res2["data"]['courses']['normal']["interaction"]
                assert l_interaction2 - l_interaction1 == 1
                break
            except:
                time.sleep(.5)
        else:
            assert False, "5s内孩子今日学习详情未更新成功！"
        for i in range(10):
            try:
                # 上报事件后，生成指定孩子的学习情况报表数据
                report_res2 = self.learning.daily_learning_report(self.authorization, self.kid_id, self.today)
                r_interaction2 = report_res2["data"]['summary']['stats']["interaction"]
                assert r_interaction2 - r_interaction1 == 1
                r_duration2 = report_res2["data"]['summary']['stats']["duration"]
                assert r_duration2 - r_duration1 == 6
                break
            except:
                time.sleep(.5)
        else:
            assert False, "5s内生成指定孩子的学习情况报表数据失败！"

    def test_interaction_lesson_event_LessonUserInteraction(self, get_courseIds):
        """上报用户交互事件 - 课程事件 - LessonUserInteraction"""
        # 上报用户交互事件
        course_id = get_courseIds[0]
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "LessonUserInteraction",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "lesson_id": course_id,
                    "interaction_type": "tap",
                    "component_key": "scene_1_question_2"
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_lesson_event_ChallengeLessonStart(self, get_courseIds):
        """上报用户交互事件 - 课程事件 - ChallengeLessonStart"""
        # 上报用户交互事件
        course_id = get_courseIds[0]
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "ChallengeLessonStart",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "course_id": course_id,
                    "interaction_type": "medium"
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_lesson_event_ChallengeLessonEnd(self, get_courseIds):
        """上报用户交互事件 - 课程事件 - ChallengeLessonEnd"""
        # 上报事件前，获取孩子今日学习详情
        learning_res1 = self.learning.daily_learning(self.authorization, self.kid_id)
        l_duration1 = learning_res1["data"]['courses']['challenge']["duration"]
        # 上报事件前，生成指定孩子的学习情况报表数据
        report_res1 = self.learning.daily_learning_report(self.authorization, self.kid_id, self.today)
        r_duration1 = report_res1["data"]['summary']['stats']["duration"]
        # 上报用户交互事件
        course_id = get_courseIds.split(',')[0]
        timestamp_milliseconds1 = int(time.time() * 1000) - 1000
        timestamp_milliseconds2 = int(time.time() * 1000)
        timestamp_milliseconds3 = int(time.time() * 1000) + 1000
        courses = [
            {
                "eventName": "ChallengeLessonStart",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds1,
                    "course_id": course_id,
                    "interaction_type": "medium"
                }
            },
            {
                "eventName": "LessonUserInteraction",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds2,
                    "lesson_id": course_id,
                    "interaction_type": "tap",
                    "component_key": "scene_1_q1"
                }
            },
            {
                "eventName": "ChallengeLessonEnd",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds3,
                    "course_id": course_id,
                    "duration": 480,
                    "answers": 10,
                    "correct_answers": 8,
                    "score": 80
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 3, f"接口返回data数据异常：{event_res['data']}"
        for i in range(10):
            try:
                # 上报事件后，获取孩子今日学习详情
                learning_res2 = self.learning.daily_learning(self.authorization, self.kid_id)
                l_duration2 = learning_res2["data"]['courses']['challenge']["duration"]
                assert l_duration2 - l_duration1 == 8
                break
            except:
                time.sleep(.5)
        else:
            assert False, "5s内孩子今日学习详情未更新成功！"
        for i in range(10):
            try:
                # 上报事件后，生成指定孩子的学习情况报表数据
                report_res2 = self.learning.daily_learning_report(self.authorization, self.kid_id, self.today)
                r_duration2 = report_res2["data"]['summary']['stats']["duration"]
                assert r_duration2 - r_duration1 == 8
                break
            except:
                time.sleep(.5)
        else:
            assert False, "5s内生成指定孩子的学习情况报表数据失败！"

    def test_interaction_lesson_event_ChallengeSettleReward(self, get_courseIds):
        """上报用户交互事件 - 课程事件 - LessonQuit"""
        # 上报用户交互事件
        course_id = get_courseIds[0]
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "ChallengeSettleReward",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "course_id": course_id,
                    "reward_type": "coin",
                    "reward_amount": 50
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_lesson_event_LessonQuit(self, get_courseIds):
        """上报用户交互事件 - 课程事件 - LessonQuit"""
        # 上报用户交互事件
        course_id = get_courseIds[0]
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "LessonQuit",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "lesson_id": course_id,
                    "quit_reason": "user_close_app"
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_story_event_StoryBookStart(self, get_bookIds):
        """上报用户交互事件 - 故事书事件 - StoryBookStart"""
        # 上报用户交互事件
        book_id = get_bookIds[0]
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "StoryBookStart",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "book_id": book_id,
                    "from_page": "home_story_tab"
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_book_event_StoryBookComplete(self, get_bookIds):
        """上报用户交互事件 - 故事书事件 - StoryBookComplete"""
        # 上报用户交互事件
        learning_res1 = self.learning.daily_learning(self.authorization, self.kid_id)
        l_duration1 = learning_res1['data']['storybooks']['duration']
        report_res1 = self.learning.daily_learning_report(self.authorization, self.kid_id, self.today)
        r_duration1 = report_res1['data']['summary']['stats']['duration']
        story_res1 = self.learning.daily_storybook_report(self.authorization, self.kid_id, self.today)
        if 'durationComparison' in story_res1["data"]:
            s_duration1 = story_res1["data"]['durationComparison']['userDuration']
        else:
            s_duration1 = 0
        # 获取有效的kidId
        book_id = get_bookIds[0]
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "StoryBookComplete",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timestamp": timestamp_milliseconds,
                    "timezone": "Asia/Shanghai",
                    "book_id": book_id,
                    "duration": 300,    # 秒，可随便写个非0值测试
                    "pages_read": 20,   # 可选，主要用于业务自用
                    "words_read": 800   # 可选
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"
        for i in range(10):
            try:
                learning_res2 = self.learning.daily_learning(self.authorization, self.kid_id)
                l_duration2 = learning_res2['data']['storybooks']['duration']
                assert l_duration2 - l_duration1 == 5
                break
            except:
                time.sleep(.5)
        else:
            assert False
        for i in range(10):
            try:
                report_res2 = self.learning.daily_learning_report(self.authorization, self.kid_id, self.today)
                r_duration2 = report_res2['data']['summary']['stats']['duration']
                assert r_duration2 - r_duration1 == 5
                break
            except:
                time.sleep(.5)
        else:
            assert False
        for i in range(10):
            try:
                story_res2 = self.learning.daily_storybook_report(self.authorization, self.kid_id, self.today)
                s_duration2 = story_res2["data"]['durationComparison']['userDuration']
                assert s_duration2 - s_duration1 == 5
                break
            except:
                time.sleep(.5)
        else:
            assert False

    def test_interaction_story_event_StoryBookExit(self, get_bookIds):
        """上报用户交互事件 - 故事书事件 - FlashCardNewStudyStart"""
        # 上报用户交互事件
        book_id = get_bookIds[0]
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "StoryBookExit",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "book_id": book_id,
                    "current_page": 3,
                    "exit_reason": "user_back"
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_flashcard_event_FlashCardNewStudyStart(self):
        """上报用户交互事件 - 闪卡事件 - FlashCardNewStudyStart"""
        # 上报用户交互事件
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "FlashCardNewStudyStart",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "session_id": 'fc_review_001',
                    "word_ids": [101, 102, 103]
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_flashcard_event_FlashCardThemeStudyComplete(self):
        """上报用户交互事件 - 闪卡事件 - FlashCardThemeStudyComplete"""
        # 上报用户交互事件
        learning_res1 = self.learning.daily_learning(self.authorization, self.kid_id)
        l_duration1 = learning_res1['data']['storybooks']['duration']
        report_res1 = self.learning.daily_learning_report(self.authorization, self.kid_id, self.today)
        challenge_res1 = self.learning.daily_flashcard_report(self.authorization, self.kid_id, self.today)
        # 获取有效的kidId
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "FlashCardThemeStudyComplete",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "word_ids": [101, 102, 201], # 本次主题学习涉及的单词ID（flash_cards_words.id）
                    "correct_first_count": 2, # 首次答对的单词数量，用来算正确率
                    "duration": 180 # 本次学习时长（秒，可选，用于统计时长）
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"
        learning_res1 = self.learning.daily_learning(self.authorization, self.kid_id)
        l_duration1 = learning_res1['data']['storybooks']['duration']
        report_res1 = self.learning.daily_learning_report(self.authorization, self.kid_id, self.today)
        challenge_res1 = self.learning.daily_flashcard_report(self.authorization, self.kid_id, self.today)

    def test_interaction_flashcard_event_FlashCardThemeStudyStart(self):
        """上报用户交互事件 - 闪卡事件 - FlashCardThemeStudyStart"""
        # 上报用户交互事件
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "FlashCardThemeStudyStart",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "theme_id": "animals",
                    "word_ids": [201, 202, 203]
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_flashcard_event_FlashCardReviewStart(self):
        """上报用户交互事件 - 闪卡事件 - FlashCardReviewStart"""
        # 上报用户交互事件
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "FlashCardReviewStart",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "session_id": 'fc_review_001',
                    "word_ids": [101, 102, 201]
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_flashcard_event_FlashCardReviewCompelete(self):
        """上报用户交互事件 - 闪卡事件 - FlashCardReviewCompelete"""
        # 上报用户交互事件
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "FlashCardReviewCompelete",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "session_id": 'fc_review_001',
                    "word_ids": [101, 102, 201],
                    "correct_first_count": 2
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_flashcard_event_FlashCardLetterStudyStart(self):
        """上报用户交互事件 - 闪卡事件 - FlashCardLetterStudyStart"""
        # 上报用户交互事件
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "FlashCardLetterStudyStart",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "letter": "A",
                    "word_ids": [301, 302]
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_flashcard_event_FlashCardLetterStudyComplete(self):
        """上报用户交互事件 - 闪卡事件 - FlashCardLetterStudyComplete"""
        # 上报用户交互事件
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "FlashCardLetterStudyComplete",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "letter": "A",
                    "word_ids": [301, 302],
                    "correct_first_count": 2
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_flashcard_event_FlashCardCvcStudyStart(self):
        """上报用户交互事件 - 闪卡事件 - FlashCardCvcStudyStart"""
        # 上报用户交互事件
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "FlashCardCvcStudyStart",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "pattern": "CVC",
                    "word_ids": [401, 402]
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_flashcard_event_FlashCardCvcStudyComplete(self):
        """上报用户交互事件 - 闪卡事件 - FlashCardCvcStudyComplete"""
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "FlashCardCvcStudyComplete",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "pattern": "CVC",
                    "word_ids": [401, 402],
                    "correct_first_count": 1
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_flashcard_event_FlashCardMathStudyStart(self):
        """上报用户交互事件 - 闪卡事件 - FlashCardMathStudyStart"""
        # 上报用户交互事件
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "FlashCardMathStudyStart",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "topic": "addition",
                    "question_count": 5
                }
            }
        ]
        # 获取孩子学习统计数据
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"

    def test_interaction_flashcard_event_FlashCardMathStudyComplete(self):
        """上报用户交互事件 - 闪卡事件 - FlashCardMathStudyComplete"""
        # 上报用户交互事件
        timestamp_milliseconds = int(time.time() * 1000)
        courses = [
            {
                "eventName": "FlashCardMathStudyComplete",
                "params": {
                    "user_id": self.user_id,
                    "child_id": self.kid_id,
                    "child_name": self.kid_name,
                    "timezone": "+08:00",
                    "timestamp": timestamp_milliseconds,
                    "topic": "addition",
                    "question_count": 5,
                    "correct_first_count": 4
                }
            }
        ]
        event_res = self.learning.interactionEvent(self.authorization, courses, DeviceType="web")
        assert isinstance(event_res, dict), f'接口返回类型异常: {type(event_res)}'
        assert event_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{event_res['code']}】"
        assert event_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{event_res['message']}】"
        assert event_res['data']['recordedCount'] == 1, f"接口返回data数据异常：{event_res['data']}"