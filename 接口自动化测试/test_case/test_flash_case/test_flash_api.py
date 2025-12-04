import pytest
import time

from config import RunConfig
from test_case.page_api.flash_cards.flash_cards_api import Flash_cardsApi

base_url = RunConfig.baseurl

@pytest.mark.flashcard
class TestFlashcardApi:
    """
    闪卡 接口测试用例
    """

    def setup_class(self):
        self.flashcard = Flash_cardsApi()
        self.auth = self.flashcard.get_authorization()[0]