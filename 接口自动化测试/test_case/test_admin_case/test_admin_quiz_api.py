import sys
import os


from test_case.page_api.admin.admin_quiz_api import AdminQuizApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminCourse
class TestAdminCourse:

    def setup_class(self):
        self.admin = AdminQuizApi()
        self.authorization = self.admin.get_admin_authorization()[0]