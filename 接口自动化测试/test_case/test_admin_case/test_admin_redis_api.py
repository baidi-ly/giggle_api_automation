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

    @pytest.mark.smoke
    def test_admin_redis_positive_setUserGrayscale_ok(self):
        """获取Redis Hash的所有数据"""
        # 设置灰度配置百分比
        feature = 'dibo_test' + self.now
        pl = {
            "feature": feature,
        }
        res2 = self.admin_redis.setGrayscalePercentage(self.auth_admin, **pl)
        assert res2['data']['message'] == '首次配置灰度百分比'
        # 设置单个灰度用户（写入到feature对应的hash）
        userKey = 'dibo_test_userKey' + self.now
        pl1 = {
            "feature": feature,
            "userKey": userKey
        }
        res3 = self.admin_redis.setUserGrayscale(self.auth_admin, **pl1)
        assert res3['data']['feature'] == feature
        assert res3['data']['userKey'] == userKey
        assert res3['data']['enabled'] == True
        # 获取RedisHash的所有数据
        res4 = self.admin_redis.redisHash(self.auth_admin, 'grayscale:config')
        for hash_k, hash_v in res4['data'].items():
            if hash_k == feature:
                assert hash_v == '"50"'
                # 删除RedisHash的指定field
                res5 = self.admin_redis.deleteHashField(self.auth_admin, field=hash_k, key='grayscale:config')
                assert res5['message'] == 'success'
                assert res5['data']['deleted'] == 1
        # 删除RedisHash的指定field后，获取RedisHash的所有数据
        res6 = self.admin_redis.redisHash(self.auth_admin, 'grayscale:config')
        for hash_k, hash_v in res6['data'].items():
            assert hash_k != feature