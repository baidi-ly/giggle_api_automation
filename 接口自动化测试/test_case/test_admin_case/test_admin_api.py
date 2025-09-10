import datetime
import sys
import os

from test_case.page_api.admin.admin_api import AdminApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
class TestAdmin:

    def setup_class(self):
        self.admin = AdminApi()
        self.authorization = self.admin.get_authorization()

    def test_AA_book_list_page(self):
        """
        分页查询用户创建的书籍列表-验证page，
        可参数化，参考注册正常场景
        """

        export_res = self.admin.export_byTheme(self.authorization)
        assert export_res["data"]





