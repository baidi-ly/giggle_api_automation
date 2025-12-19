import datetime
import sys
import os
import time

from pandas import DataFrame

import config
from test_case.page_api.admin.admin_course_api import AdminCourseApi
from test_case.page_api.admin.admin_gametemplate_api import AdminGametemplateApi
from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.game.game_api import GameApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.materials.materials_api import MaterialsApi

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
        self.materials = MaterialsApi()
        self.admin_game = AdminGametemplateApi()
        self.admin_course = AdminCourseApi()
        self.authorization = self.game.get_authorization()[0]
        self.admin_auth = self.admin_course.get_admin_authorization()[0]

        kids_res = self.kid.getKids(self.authorization)
        for kid in kids_res['data']:
            if kid['name'] == 'New Kid':
                self.kid_id = kid['id']
                break

    @pytest.fixture(scope="class")
    def getkidId(self):
        '''类前置 - 获取kidId'''
        kid_res = self.kid.getKids(self.authorization)
        yield kid_res['data'][0]['id']

    @pytest.mark.smoke
    def test_AA_game_search_key(self):
        """根据关键词搜索游戏内容"""
        key = "和平"
        game_res = self.game.search_game(self.authorization, key)
        assert "message" in game_res.keys(), f'根据关键词搜索游戏内容-未返回message字段'
        assert game_res['message'] == "success"
        assert "data" in game_res.keys(), f'根据关键词搜索游戏内容-未返回data字段'
        gameNames = DataFrame(game_res['data']).loc[:, "gameName"].tolist()
        for game in gameNames:
            assert key in game, f"根据关键词搜索游戏内容失败，预期内容包含：{key}，实际：{game}"

    @pytest.mark.smoke
    def test_game_positive_getVisible_ok(self):
        """查询故事书Tab是否显示"""
        # 查询故事书Tab是否显示
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
        res = self.game.getVisible(value, code=200)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data']['visible'] in [True, False], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_game_positive_drawing_word(self):
        """画词"""
        word = "cat"
        res = self.game.drawing_word(self.authorization, word)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['word'] == word, f"接口返回data数据异常：{res['data']}"
        assert res['data']['lexileLevel'] == 200, f"接口返回data数据异常：{res['data']}"
        # 下载单词封面
        wordCover = res['data']['wordCover']
        fileName1 = 'wordCover'
        self.materials.download_materials(self.authorization, wordCover, fileName1, fileType="png")
        # 下载图像描线边缘
        lineDrawingImage = res['data']['lineDrawingImage']
        fileName2 = 'lineDrawingImage'
        # 下载动画
        self.materials.download_materials(self.authorization, lineDrawingImage, fileName2, fileType="png")
        animation = res['data']['animation']
        fileName3 = 'animation'
        self.materials.download_materials(self.authorization, animation, fileName3, fileType="gif")
        # 下载动画发音
        pronunciation = res['data']['pronunciation']
        fileName4 = 'pronunciation'
        self.materials.download_materials(self.authorization, pronunciation, fileName4, fileType="mp3")

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

    @pytest.mark.smoke
    def test_game_positive_published_play_zones(self):
        """获取所有已发布的游戏列表"""
        # 获取所有已发布的游戏列表
        playZoneId = self.game.published_play_zones(self.authorization)['data']['content'][0]['id']
        # 获取playZone价格
        res = self.game.get_playzone_price(self.authorization, playZoneId)
        playZone_info = {
            "isPurchased": False,
            "name": "video test",
            "playZoneId": 703396694306885,
            "plays": 3,
            "points": 0,
            "remainingPlays": 0
        }
        assert res['data'] == playZone_info

    def test_game_positive_get_playzone_invalid(self):
        """playZone价格"""
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
    def test_game_positive_getLearningstatus_ok(self, kid_data_session, get_course_ids_session):
        """记录孩子完成一门课程的学习"""
        # 获取测试学生
        kid_id = kid_data_session[0]
        # 获取孩子学习状态
        status_res1 = self.game.getLearningstatus(self.authorization, kid_id)['data']
        assert not status_res1
        # 获取课程详情包括版本信息
        course_id = get_course_ids_session[0]
        # 获取课程详情包括版本信息
        course_name = self.admin_course.course_details(self.admin_auth, course_id)['data']['course']['name']
        # 记录孩子完成一门课程的学习
        complete_res = self.game.completelearning(self.authorization, course_id, kid_id, course_name)['data']
        complete_data = [
            {
                "giggles": 20,
                "id": "1",
                "name": "首次学习",
                "propAmount": 0,
                "propId": None,
                "status": 1,
                "times": None,
                "type": 1
            }
        ]
        assert complete_res == complete_data
        # 再次获取孩子学习状态
        res = self.game.getLearningstatus(self.authorization, kid_id)
        assert res['message'] == 'success'
        assert res['data'][0]['learnedCount'] == 1
        assert res['data'][0]['lessonId'] == course_id
        assert res['data'][0]['lessonName'] == course_name

    @pytest.mark.smoke
    def test_game_positive_reportReviewedWords_ok(self, kid_data_session, get_course_ids_session):
        """上报学习过的单词"""
        # 获取测试学生
        kid_id = kid_data_session[0]
        # 获取课程详情包括版本信息
        course_id = get_course_ids_session[0]
        courseIds = [course_id]
        # 搜索课程单词列表
        UnreviewedWords = self.admin_course.getCourseWords(self.authorization, course_id)
        assert UnreviewedWords
        # 获取未复习的单词
        pl = {
          "kidId": kid_id,
          "courseIds": courseIds
        }
        unreviewed_res = self.game.getUnreviewedWords(self.authorization, **pl)
        word_ids = DataFrame(unreviewed_res['data'])['id'].tolist()
        # 上报学习过的单词
        pl1 = {
            "kidId": kid_id,
            "lessonId": course_id,
            "wordIds": word_ids
        }
        res = self.game.reportReviewedWords(self.authorization, **pl1)
        assert res['message'] == 'success'
        time.sleep(1)
        # 再次获取未复习的单词
        unreviewed_res2 = self.game.getUnreviewedWords(self.authorization, **pl)
        assert not unreviewed_res2['data']

    @pytest.mark.smoke
    def test_game_positive_getDailyLearning_ok(self, kid_data_session):
        """检查用户今日是否完成学习"""
        # 获取测试学生
        kid_id = kid_data_session[0]
        # 检查用户今日是否完成学习
        daily_res = self.game.getDailyLearning(self.authorization, kid_id)['data']
        assert not daily_res
        # 记录用户今日学习完成状态
        res = self.game.recorde_dailyLearning(self.authorization, kid_id)
        assert res['message'] == 'success'
        # zaic检查用户今日是否完成学习
        daily_res = self.game.getDailyLearning(self.authorization, kid_id)['data']
        assert daily_res
