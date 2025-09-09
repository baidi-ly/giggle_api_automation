import datetime
import sys
import os
from time import strftime

from test_case.page_api.book.book_api import BookApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.book
class TestBook:

    def setup_class(self):
        self.book = BookApi()
        self.authorization = self.book.get_authorization()
        self.now = strftime("%Y%m%d%H%M%S")

    def teardown_class(self):
        '''
        所有用例执行完之后执行，可执行动作，清理所有注册的数据
        本次测试mock只创建了注册接口，未创建清除注册用户接口，暂无代码
        '''
        pass

    @pytest.fixture(scope="class")
    def get_bookId(self):
        '''方法前置 - 创建kidId'''
        # 创建小孩账户
        bookName = '前置书籍'+self.now
        category  = 1
        seriesId = 1
        storyType = ''
        bookList = self.book.book_list(self.authorization)
        yield bookList

    @pytest.mark.pendingRelease
    @pytest.mark.parametrize("isTranslatable", [True, False], ids=[True, False])
    def test_book_translationSetting_update_normal(self, isTranslatable, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.update_translationSetting(self.authorization, bookId, isTranslatable)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == "更新成功"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_translationSetting_update_bookId_not_exist(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.update_translationSetting(self.authorization, bookId)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == 'book not found'
        assert event_res["message"] == 'book not found'


    @pytest.mark.pendingRelease
    def test_book_translationSetting_update_bookId_not_current_owner(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        pass

    @pytest.mark.pendingRelease
    def test_book_translationSetting_update_bookId_empty(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        self.book.update_translationSetting(self.authorization, '', code=403)

    @pytest.mark.pendingRelease
    def test_book_translationSetting_update_isTranslatable_wrong(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.update_translationSetting(self.authorization, bookId, '9999', code=400)
        assert event_res["data"] == "Failed to convert value of type 'java.lang.String' to required type 'boolean'; nested exception is java.lang.IllegalArgumentException: Invalid boolean value [9999]"
        assert event_res["message"] == 'invalid parameter'


    @pytest.mark.pendingRelease
    def test_book_get_translationSetting_bookId_normal(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.translationSetting(self.authorization, bookId)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"]["isTranslatable"] == False
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_get_translationSetting_bookId_not_exist(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.translationSetting(self.authorization, bookId)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == 'book not found'
        assert event_res["message"] == 'book not found'

    @pytest.mark.pendingRelease
    def test_book_get_translationSetting_bookId_not_current_owner(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        pass

    @pytest.mark.pendingRelease
    def test_book_get_translationSetting_bookId_empty(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        self.book.translationSetting(self.authorization, '', code=403)


    @pytest.mark.pendingRelease
    @pytest.mark.parametrize("word, interfaceLanguage, learningLanguage, header",
                             [("hello", "en", "en", 'hello · hello'),
                              ("", "en", "en",'happy · happy'),
                              ("hello", "en", "zh", 'hello · 你好'),
                              ("hello", "zh", "en", '你好 · hello'),   # TODO
                              ("hello", "zh", "zh", '你好 · 你好')], ids=["en_en", "default", "en_ch", "ch_en", "ch_ch"])
    def test_book_getWordDefinition_word_normal(self, word, interfaceLanguage, learningLanguage, header):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.getWordDefinition(self.authorization, word, interfaceLanguage, learningLanguage)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"]["header"] == header
        res_interfaceDefin = event_res["data"]['interfaceDefinition']
        res_learningDefin = event_res["data"]['learningDefinition']
        assert self.book.check_str_type(res_interfaceDefin) == interfaceLanguage
        assert self.book.check_str_type(res_learningDefin) == learningLanguage


    @pytest.mark.pendingRelease
    def test_book_generateVideo_bookId_normal(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.generateVideo(self.authorization, bookId)     # TODO
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_generateVideo_bookId_not_exist(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.generateVideo(self.authorization, bookId)   # TODO
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_generateVideo_bookId_not_current_owner(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        pass

    @pytest.mark.pendingRelease
    def test_book_generateVideo_bookId_empty(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.generateVideo(self.authorization, '')   # TODO
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_get_generateVideo_bookId_normal(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.get_generateVideos(self.authorization, bookId)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_get_generateVideo_bookId_not_exist(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.get_generateVideos(self.authorization, bookId)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert False    # TODO

    @pytest.mark.pendingRelease
    def test_book_get_generateVideo_bookId_not_current_owner(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        pass

    @pytest.mark.pendingRelease
    def test_book_get_generateVideo_bookId_empty(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.get_generateVideos(self.authorization, '', code=400)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'invalid parameter'
        assert event_res['data'] == '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: ""'''