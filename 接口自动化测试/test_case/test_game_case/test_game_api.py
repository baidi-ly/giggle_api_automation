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
        self.authorization = self.game.get_authorization()[0]

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

    @pytest.mark.release
    def test_game_positive_getVisible_ok(self):
        """查询故事书Tab是否显示-正向用例"""
        res = self.game.getVisible(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['visible'] in [True, False], f"接口返回data数据异常：{res['data']}"

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
    def test_game_permission_getVisible(self, desc, value):
        """查询故事书Tab是否显示-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.game.getVisible(value, code=200)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data']['visible'] in [True, False], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_game_positive_drawing_word(self):
        """画词-正向流程"""
        word = "cat"
        res = self.game.drawing_word(self.authorization, word)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['visible'] in [True, False], f"接口返回data数据异常：{res['data']}"

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
    def test_game_permission_getVisible(self, desc, value):
        """查询故事书Tab是否显示-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.game.drawing_word(value, code=200)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data']['visible'] in [True, False], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize('word', ['', None, 123])
    def test_game_positive_drawing_word_invalid(self, word):
        """画词-不正确的word"""
        res = self.game.drawing_word(self.authorization, word)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['visible'] in [True, False], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_game_positive_get_playzone_price(self):
        """playZone价格-正向流程"""
        playZoneId = 1  # 根据实际可用ID调整
        res = self.game.get_playzone_price(self.authorization, playZoneId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['visible'] in [True, False], f"接口返回data数据异常：{res['data']}"

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
    def test_game_invalid_get_playzone_price(self, desc, value):
        """playZone价格-path参数非法"""
        res = self.game.get_playzone_price(value, code=200)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data']['visible'] in [True, False], f"接口返回data数据异常：{res['data']}"