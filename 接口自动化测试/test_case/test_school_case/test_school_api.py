import pytest

from test_case.page_api.school.school_api import SchoolApi
from config import RunConfig

base_url = RunConfig.baseurl

class TestSchoolApi:
    """
    school 接口测试用例
    """

    def setup_class(self):
        self.school = SchoolApi()
        self.authorization = self.school.get_authorization()