import sys
import os
from time import strftime

from test_case.page_api.tag.tag_api import TagApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.tag
class TestTag:

    def setup_class(self):
        self.tag = TagApi()
        self.authorization = self.tag.get_authorization()[0]
        self.now = strftime("%Y%m%d%H%M%S")