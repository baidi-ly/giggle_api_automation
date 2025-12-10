import datetime
import sys
import os
from pandas import DataFrame

import config
from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.game.game_api import GameApi
from test_case.page_api.kid.kid_api import KidApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.game
class TestGame:

    def setup_class(self):
        self.game = GameApi()
        self.kid = KidApi()
        self.course = CourseApi()
        self.authorization = self.game.get_authorization()[0]

        kids_res = self.kid.getKids(self.authorization)
        for kid in kids_res['data']:
            if kid['name'] == 'New Kid':
                self.kid_id = kid['id']
                break

    def teardown_class(self):
        '''
        所有用例执行完之后执行，可执行动作，清理所有注册的数据
        本次测试mock只创建了注册接口，未创建清除注册用户接口，暂无代码
        '''
        pass

    @pytest.fixture(scope="class")
    def getkidId(self):
        '''类前置 - 获取kidId'''
        kid_res = self.kid.getKids(self.authorization)
        yield kid_res['data'][0]['id']

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

    @pytest.mark.smoke
    def test_game_positive_getVisible_ok(self):
        """查询故事书Tab是否显示-正向用例"""
        res = self.game.getVisible(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['visible'] in [True, False], f"接口返回data数据异常：{res['data']}"

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

    def test_game_positive_drawing_word(self):
        """画词-正向流程"""
        word = "cat"
        res = self.game.drawing_word(self.authorization, word)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['word'] == word, f"接口返回data数据异常：{res['data']}"

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
        res = self.game.drawing_word(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data']['visible'] in [True, False], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize('word', ['', None, 123])
    def test_game_positive_drawing_word_invalid(self, word):
        """画词-不正确的word"""
        if word == None:
            res = self.game.drawing_word(self.authorization, word, code=500)
        else:
            res = self.game.drawing_word(self.authorization, word)
        if word == None:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【internal server error】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
        else:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 100149, f"接口返回状态码异常: 预期【100149】，实际【{res['code']}】"
            assert res['message'] == 'Course word not found', f"接口返回message信息异常: 预期【Course word not found】，实际【{res['message']}】"
            assert res['data'] == 'Course word not found', f"接口返回data数据异常：{res['data']}"

    def test_game_positive_get_playzone_price(self):
        """playZone价格-正向流程"""
        playZoneId = self.game.published_play_zones(self.authorization)['data']['content'][0]['id']
        res = self.game.get_playzone_price(self.authorization, playZoneId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【100054】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['playZoneId'] == playZoneId, f"接口返回data数据异常：{res['data']}"

    def test_game_positive_get_playzone_invalid(self):
        """playZone价格-正向流程"""
        playZoneId = 1
        res = self.game.get_playzone_price(self.authorization, playZoneId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100054, f"接口返回状态码异常: 预期【100054】，实际【{res['code']}】"
        assert res['message'] == 'Resource not found', f"接口返回message信息异常: 预期【Resource not found】，实际【{res['message']}】"
        assert res['data'] == 'Resource not found', f"接口返回data数据异常：{res['data']}"

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
        res = self.game.get_playzone_price(value, playZoneId=1, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data']['visible'] in [True, False], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_game_positive_getLearningstatus_ok(self, getkidId):
        """获取孩子学习状态-正向用例"""
        kid_id = getkidId
        res = self.game.getLearningstatus(self.authorization, kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_game_positive_getUnreviewedWords_ok(self, getkidId):
        """获取未复习的单词-正向用例"""
        kid_id = getkidId
        learningStatus_res = self.game.getLearningstatus(self.authorization, kid_id)
        courseIds = DataFrame(learningStatus_res['data'])['lessonId'].tolist()
        pl = {
          "kidId": kid_id,
          "courseIds": courseIds
        }
        res = self.game.getUnreviewedWords(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_game_positive_reportReviewedWords_ok(self, getkidId):
        """上报学习过的单词-正向用例"""
        kid_id = getkidId
        learningStatus_res = self.game.getLearningstatus(self.authorization, kid_id)
        courseIds_res = DataFrame(learningStatus_res['data'])['lessonId'].tolist()
        courseIds = courseIds_res[:1]
        lesson_id = courseIds_res[0]
        pl = {
          "kidId": kid_id,
          "courseIds": courseIds
        }
        unreviewed_res = self.game.getUnreviewedWords(self.authorization, **pl)
        word_ids = DataFrame(unreviewed_res['data'])['id'].tolist()
        pl1 = {
            "kidId": kid_id,
            "lessonId": lesson_id,
            "wordIds": word_ids
        }
        res = self.game.reportReviewedWords(self.authorization, **pl1)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert not res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_game_positive_dailyLearning_ok(self):
        """记录用户今日学习完成状态-正向用例"""
        res = self.game.recorde_dailyLearning(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == None, f"接口返回data数据异常：{res['data']}"

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
    def test_game_permission_dailyLearning(self, desc, value):
        """记录用户今日学习完成状态-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.game.recorde_dailyLearning(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_game_positive_getDailyLearning_ok(self):
        """检查用户今日是否完成学习-正向用例"""
        res = self.game.getDailyLearning(self.authorization)
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
    def test_game_permission_getDailyLearning(self, desc, value):
        """检查用户今日是否完成学习-权限测试"""
        res = self.game.getDailyLearning(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize('level', [1,2,4,5,8])
    def test_game_positive_queryCourseStrategy_ok(self, level):
        """查询课程策略配置-正向用例"""
        # 获取推荐课程列表
        recommends_res = self.course.getFixOrderRecommend(self.authorization, learningLevel='L1')
        courseId = recommends_res['data'][0]['courseId']
        res = self.game.queryCourseStrategy(self.authorization, courseId, level)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == {
            "matchType": "LEVEL_STRATEGY",
            "matched": True,
            "ruleInfo": {
                "courseIds": None,
                "levelRange": f"L{level}"
            },
            "strategyConfig": {
                "description": "test",
                "enabled": True,
                "pattern": "true,false,false,true,false,false",
                "patternBehavior": "STICK_TO_LAST",
                "resetOnSegmentChange": False
            },
            "strategyId": "howell"
        }