
import sys
import os

from test_case.page_api.admin.admin_flashcards_api import AdminFlashcardsApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminFlashcard
class TestAdminFlashcard:

    def setup_class(self):
        self.admin_flashcard = AdminFlashcardsApi()
        self.authorization = self.admin_flashcard.get_admin_authorization()[0]