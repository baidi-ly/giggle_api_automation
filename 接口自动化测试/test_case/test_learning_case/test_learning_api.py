import pytest
import sys
import os

from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.learning.learning_api import LearningApi

sys.path.append(os.getcwd())
sys.path.append("..")


@pytest.mark.Learning
class TestLearning:

    def setup_class(self):
        self.learning = LearningApi()
        self.authorization = self.learning.get_authorization()
        self.kid = KidApi()

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

    @pytest.mark.pendingRelease
    def test_learning_stats_byKidId_normal(self, getkidId):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.learning_stats(kidId, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_stats_byKidId_deletedAccount(self, create_deletedAccount):
        """注销的kidId，返回错误信息"""
        # 获取有效的kidId
        kidId = create_deletedAccount
        # 获取孩子学习统计数据
        stats_res = self.learning.learning_stats(kidId, self.authorization)
        assert "msg" in stats_res, f"获取孩子学习统计数据接口没有msg数据，response->{stats_res}"
        assert stats_res["msg"] == "无效的kidId", f'无效的kidId返回错误信息有误，预期:无效的kidId, 实际：{stats_res["msg"]}'

    @pytest.mark.pendingRelease
    def test_learning_stats_byKidId_invalid(self):
        """无效的kidId - 返回错误信息"""
        # 创建无效的kidId
        kidId = 9999999
        # 获取孩子学习统计数据
        stats_res = self.learning.learning_stats(kidId, self.authorization)
        assert "msg" in stats_res, f"获取孩子学习统计数据接口没有msg数据，response->{stats_res}"
        assert stats_res["msg"] == "无效的kidId", f'无效的kidId返回错误信息有误，预期:无效的kidId, 实际：{stats_res["msg"]}'

    @pytest.mark.pendingRelease
    def test_learning_stats_byKidId_unauthorized(self, getkidId):
        """有效的kidId - 未授权，返回401"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 未授权，获取孩子学习统计数据
        self.learning.learning_stats(kidId)

    @pytest.mark.pendingRelease
    def test_learning_stats_byKidId_negative(self, getkidId):
        """kidId为负数 - 返回错误信息"""
        # 创建负数kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.learning_stats(kidId, self.authorization)
        assert "msg" in stats_res, f"获取孩子学习统计数据接口没有msg数据，response->{stats_res}"
        assert stats_res["msg"] == "无效的kidId", f'kidId为负数返回错误信息有误，预期:无效的kidId, 实际：{stats_res["msg"]}'

    @pytest.mark.pendingRelease
    def test_learning_daily_byKidId_normal(self, getkidId):
        """获取今日学习详情，有数据的kidId，返回完整统计数据"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.daily_learning(kidId, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_daily_byKidId_normal_empty(self, getkidId):
        """获取今日学习详情，无数据的kidId，返回完整统计数据"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.daily_learning(kidId, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_daily_byKidId_normal(self, getkidId):
        """获取今日学习详情，跨时区测试"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.daily_learning(kidId, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_stats_byKidId_deletedAccount(self, create_deletedAccount):
        """获取今日学习详情，注销的kidId，返回错误信息"""
        # 获取有效的kidId
        kidId = create_deletedAccount
        # 获取孩子学习统计数据
        stats_res = self.learning.daily_learning(kidId, self.authorization)
        assert "msg" in stats_res, f"获取孩子学习统计数据接口没有msg数据，response->{stats_res}"
        assert stats_res["msg"] == "无效的kidId", f'无效的kidId返回错误信息有误，预期:无效的kidId, 实际：{stats_res["msg"]}'

    @pytest.mark.pendingRelease
    def test_learning_daily_byKidId_invalid(self):
        """无效的kidId - 返回错误信息"""
        # 创建无效的kidId
        kidId = 9999999
        # 获取孩子学习统计数据
        stats_res = self.learning.daily_learning(kidId, self.authorization)
        assert "msg" in stats_res, f"获取孩子学习统计数据接口没有msg数据，response->{stats_res}"
        assert stats_res["msg"] == "无效的kidId", f'无效的kidId返回错误信息有误，预期:无效的kidId, 实际：{stats_res["msg"]}'

    @pytest.mark.pendingRelease
    def test_learning_daily_byKidId_unauthorized(self, getkidId):
        """有效的kidId - 未授权，返回401"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 未授权，获取孩子学习统计数据
        self.learning.daily_learning(kidId)

    @pytest.mark.pendingRelease
    def test_learning_daily_byKidId_negative(self, getkidId):
        """kidId为负数 - 返回错误信息"""
        # 创建负数kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.daily_learning(kidId, self.authorization)
        assert "msg" in stats_res, f"获取孩子学习统计数据接口没有msg数据，response->{stats_res}"
        assert stats_res["msg"] == "无效的kidId", f'kidId为负数返回错误信息有误，预期:无效的kidId, 实际：{stats_res["msg"]}'

    @pytest.mark.pendingRelease
    def test_learning_daily_report_byKidId_normal(self, getkidId):
        """生成指定孩子的学习情况报表数据，生成今日报表"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.daily_learning_report(kidId, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_daily_report_byKidId_normal(self, getkidId):
        """生成指定孩子的学习情况报表数据，生成今日报表"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.daily_learning_report(kidId, self.authorization, date="2025-01-26")
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_daily_report_byKidId_normal(self, getkidId):
        """生成指定孩子的学习情况报表数据，生成今日报表"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.daily_learning_report(kidId, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_weekly_byKidId_thisWeekend(self, getkidId):
        """获取本周学习"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.weekly_learning(kidId, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_weekly_byKidId_nextWeekend(self, getkidId):
        """跨周测试 - 下一周"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.weekly_learning(kidId, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_weekly_byKidId_lastWeekend(self, getkidId):
        """跨周测试 - 上一周"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.weekly_learning(kidId, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_weekly_learning_report_thisWeekend(self, getkidId):
        """跨周测试 - 下一周"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        stats_res = self.learning.weekly_learning_report(kidId, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_weekly_learning_report_targetWeekend(self, getkidId):
        """跨周测试 - 上一周"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        startDate = "2025-01-20"
        endDate = "2025-01-26"
        stats_res = self.learning.weekly_learning_report(kidId, self.authorization, startDate, endDate)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_daily_storybook_report_normal(self, getkidId):
        """生成今日故事书报告"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        date = "2025-01-20"
        stats_res = self.learning.daily_storybook_report(kidId, date, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]

    @pytest.mark.pendingRelease
    def test_learning_daily_storybook_report_empty(self, getkidId):
        """无故事书阅读记录"""
        # 获取有效的kidId
        kidId = getkidId[0]["id"]
        # 获取孩子学习统计数据
        date = "2025-01-26"
        stats_res = self.learning.daily_storybook_report(kidId, date, self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]