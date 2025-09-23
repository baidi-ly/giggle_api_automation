import datetime
import sys
import os
from pandas import DataFrame

from test_case.page_api.donate.donate_api import DonateApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.donate
class TestDonate:

    def setup_class(self):
        self.doante = DonateApi()
        self.authorization = self.game.get_authorization()