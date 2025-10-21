import datetime
import sys
import os

from test_case.page_api.admin.admin_book_api import AdminBookApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminActivity
class TestAdminActivity:

    def setup_class(self):
        self.admin_book = AdminBookApi()
        self.authorization = self.admin_book.get_admin_authorization()
