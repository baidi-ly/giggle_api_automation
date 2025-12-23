import sys
import os
from time import strftime

import config
from test_case.page_api.admin.admin_redis_api import AdminRedisApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.admin
@pytest.mark.adminRedis
class TestAdminRedis:

    def setup_class(self):
        self.admin_redis = AdminRedisApi()
        self.authorization = self.admin_redis.get_authorization()[0]
        self.auth_admin = self.admin_redis.get_admin_authorization()[0]

        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.release
    def test_admin_redis_positive_setUserGrayscale_ok(self):
        """获取Redis Hash的所有数据-正向用例"""
        res1 = self.admin_redis.redisHash(self.auth_admin)
        feature = 'dibo_test' + self.now
        pl = {
            "feature": feature,
        }
        res2 = self.admin_redis.setGrayscalePercentage(self.authorization, **pl)
        userKey = 'dibo_test_userKey' + self.now
        pl1 = {
            "feature": feature,
            "userKey": userKey
        }
        res3 = self.admin_redis.setUserGrayscale(self.authorization, **pl1)
        res4 = self.admin_redis.redisHash(self.auth_admin)
        res5 = self.admin_redis.deleteHashField(self.auth_admin)
        assert res5['message'] == 'success'