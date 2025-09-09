import datetime
import sys
import os

from test_case.page_api.book.book_api import BookApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.book
class TestBook:

    def setup_class(self):
        self.book = BookApi()
        self.authorization = self.book.get_authorization()

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
        couerseList = self.course.listAllWithLevel(self.authorization)["data"]
        yield couerseList

    @pytest.mark.pendingRelease
    @pytest.mark.parametrize("isTranslatable", [True, False], [True, False])
    def test_book_translationSetting_update_normal(self, isTranslatable, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId
        event_res = self.book.update_translationSetting(self.authorization, bookId, isTranslatable)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_translationSetting_update_bookId_not_exist(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.update_translationSetting(self.authorization, bookId, True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_translationSetting_update_bookId_not_current_owner(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.update_translationSetting(self.authorization, bookId, True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_translationSetting_update_bookId_empty(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.update_translationSetting(self.authorization, '', True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_translationSetting_update_isTranslatable_wrong(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId
        event_res = self.book.update_translationSetting(self.authorization, bookId, '9999')
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_get_translationSetting_bookId_not_exist(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.translationSetting(self.authorization, bookId, True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_get_translationSetting_bookId_not_current_owner(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.translationSetting(self.authorization, bookId, True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_get_translationSetting_bookId_empty(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.translationSetting(self.authorization, '', True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_getWordDefinition_word_normal(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        word = "hello"
        interfaceLanguage = "en"
        learningLanguage = "en"
        event_res = self.book.getWordDefinition(self.authorization, word, interfaceLanguage, learningLanguage)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_getWordDefinition_word_empty(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        word = ""
        interfaceLanguage = "en"
        learningLanguage = "en"
        event_res = self.book.getWordDefinition(self.authorization, word, interfaceLanguage, learningLanguage)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_getWordDefinition_word_empty1(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        word = "hello"
        interfaceLanguage = "en"
        learningLanguage = "zh"
        event_res = self.book.getWordDefinition(self.authorization, word, interfaceLanguage, learningLanguage)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_getWordDefinition_word_empty2(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        word = "hello"
        interfaceLanguage = "zh"
        learningLanguage = "en"
        event_res = self.book.getWordDefinition(self.authorization, word, interfaceLanguage, learningLanguage)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_getWordDefinition_word_empty3(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        word = "hello"
        interfaceLanguage = "zh"
        learningLanguage = "zh"
        event_res = self.book.getWordDefinition(self.authorization, word, interfaceLanguage, learningLanguage)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_generateVideo_bookId_normal(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.translationSetting(self.authorization, bookId, True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_generateVideo_bookId_not_exist(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.translationSetting(self.authorization, bookId, True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_generateVideo_bookId_not_current_owner(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.translationSetting(self.authorization, bookId, True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_generateVideo_bookId_empty(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.translationSetting(self.authorization, '', True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_get_generateVideo_bookId_normal(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.translationSetting(self.authorization, bookId, True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_get_generateVideo_bookId_not_exist(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.translationSetting(self.authorization, bookId, True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_get_generateVideo_bookId_not_current_owner(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.translationSetting(self.authorization, bookId, True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"

    @pytest.mark.pendingRelease
    def test_book_get_generateVideo_bookId_empty(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.translationSetting(self.authorization, '', True)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == "success"