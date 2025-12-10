from time import strftime

import pytest

from test_case.page_api.user.user_api import UserApi

user = UserApi()
authorization, userId = user.get_authorization()

@pytest.fixture(scope='session')
def kid_data_session():
    '''创建测试学生'''
    # 创建测试学生
    kid_name = 'dibo_test_kid' + strftime("%Y%m%d%H%M%S")
    kid_id = user.createkid(authorization, kid_name)['data']['id']
    yield kid_id, kid_name
    # 删除测试学生
    user.deletekid(authorization, kid_id)
