import datetime
import sys
import os

from test_case.page_api.book.book_api import BookApi
from test_case.page_api.kid.kid_api import KidApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Kid
class TestKid:

    def setup_class(self):
        self.kid = KidApi()
        self.authorization = self.book.get_authorization()

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





