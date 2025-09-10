import datetime

import pytest
import sys
import os

from test_case.page_api.poster.poster_api import PosterApi

sys.path.append(os.getcwd())
sys.path.append("..")


@pytest.mark.Poster
class TestPoster:

    def setup_class(self):
        self.poster = PosterApi()
        self.authorization = self.poster.get_authorization()

    @pytest.mark.pendingRelease
    def test_course_blockedCourseIds_normal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        posterId = 1
        stats_res = self.poster.poster_generate(self.authorization, posterId, {})
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["learningStats"]
