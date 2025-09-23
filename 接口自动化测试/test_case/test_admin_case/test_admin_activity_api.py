import datetime
import sys
import os

import pandas as pd

from test_case.page_api.admin.admin_activity_api import AdminActivityApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminActivity
class TestAdminActivity:

    def setup_class(self):
        self.admin = AdminActivityApi()
        self.authorization = self.admin.get_admin_authorization()

