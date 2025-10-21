import sys
import os

import pandas as pd

from test_case.page_api.admin.admin_tabstorybook_api import AdminTabstorybookApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminTabStoryBookApi
class TestAdminTabStoryBookApi:

    def setup_class(self):
        self.admin_tab = AdminTabstorybookApi()
        self.authorization = self.admin_tab.get_admin_authorization()
