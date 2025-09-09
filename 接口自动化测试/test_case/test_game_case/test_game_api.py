import datetime
import sys
import os
from pandas import DataFrame

from test_case.page_api.game.game_api import GameApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.game
class TestGame:

    def setup_class(self):
        self.game = GameApi()
        self.authorization = self.game.get_authorization()

    def teardown_class(self):
        '''
        所有用例执行完之后执行，可执行动作，清理所有注册的数据
        本次测试mock只创建了注册接口，未创建清除注册用户接口，暂无代码
        '''
        pass

    def test_AA_game_search_key(self):
        """根据关键词搜索游戏内容"""

        # 1. 注册新账号
        key = "和平"
        game_res = self.game.search_game(self.authorization, key)
        assert "message" in game_res.keys(), f'根据关键词搜索游戏内容-未返回message字段'
        assert game_res['message'] == "搜索成功"
        assert "data" in game_res.keys(), f'根据关键词搜索游戏内容-未返回data字段'
        gameNames = DataFrame(game_res['data']).loc[:, "gameName"].tolist()
        for game in gameNames:
            assert key in game, f"根据关键词搜索游戏内容失败，预期内容包含：{key}，实际：{game}"

    @pytest.mark.flaky(reruns=3, reruns_delay=2)
    def test_AB_game_search_size(self):
        """参考上述逻辑验证size"""
        pytest.assume(1 == 3)
        pytest.assume(2 == 3)
        pytest.assume(2 == 2)

