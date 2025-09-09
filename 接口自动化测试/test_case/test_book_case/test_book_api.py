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

    def test_AA_book_list_page(self):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """
        page = 1
        pageSize = 10
        status = 1
        book_res = self.book.book_list(self.authorization, page, pageSize, status)
        assert book_res["data"]

    def test_AB_book_list_pageSize(self):
        """分页查询用户创建的书籍列表-验证pageSize"""
        assert True
        assert False

    def test_AC_book_list_status(self):
        """分页查询用户创建的书籍列表-验证pageSize"""
        pass

    def test_AD_book_list_DeviceType(self):
        """分页查询用户创建的书籍列表-验证设备类型"""
        pass

    def test_BA_book_list_DeviceType(self):
        """根据书籍ID获取详细信息 - 正常场景"""

        bookId = 1
        translateLanguage = "zh-CN"
        book_info_res = self.book.book_detail_byId(self.authorization, bookId, translateLanguage)
        assert book_info_res["data"]





