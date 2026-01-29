import sys
import os
from time import strftime

import config
from test_case.page_api.admin.admin_curriculum_api import AdminCurriculumApi
from test_case.page_api.admin.admin_redis_api import AdminRedisApi
from test_case.page_api.curriculum.curriculum_api import CurriculumApi
from test_case.page_api.kid.kid_api import KidApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.admin
@pytest.mark.adminRedis
class TestAdminRedis:

    def setup_class(self):
        self.admin_redis = AdminRedisApi()
        self.curriculum = CurriculumApi()
        self.kid = KidApi()
        self.admin_curriculum = AdminCurriculumApi()
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

    @pytest.mark.smoke
    def test_admin_redis_positive_deleteKey_ok(self):
        """删除Redis指定key-正向用例"""
        entityType = 'unit'

        kid_res = self.kid.getKids(self.authorization)['data']
        for kid in kid_res:
            if kid['name'] == "Hehe":
                kid_id = kid['id']
                break

        # 步骤1: 获取课程路径
        curriculum_paths = self.curriculum.get_curriculum_by_country(self.authorization, countryCode='JP')
        assert curriculum_paths["code"] == 200, f"获取课程路径失败: {curriculum_paths}"
        assert curriculum_paths["data"], "没有找到课程路径"
        # 选择第一个路径
        path_id = curriculum_paths["data"]["id"]
        # 步骤2: 获取该路径下的所有学习等级
        levels = self.curriculum.get_level_list(self.authorization, path_id)['data']
        for level in levels:
            if level['levelName'] == 'Level 2':
                level_id = level['id']
                # 查询路径列表，验证新增成功
                list_res = self.admin_curriculum.curriculum_unit_list(self.auth_admin, level_id)
                for unit in list_res['data']:
                    if unit['unitName'] == 'Unit 2':
                        entityId = unit['id']
                        flag = True
                        break
                else:
                    flag = False
                if flag:
                    break

        # key = f'curriculum:push:{entityType}_progress:{kid_id}:{entityId}'
        # res = self.admin_redis.deleteKey(self.authorization, key)
        # assert res['message'] == 'success'

        entityType = 'level'
        key = f'curriculum:push:{entityType}_progress:{kid_id}:{level_id}'
        res = self.admin_redis.deleteKey(self.authorization, key)
        assert res['message'] == 'success'