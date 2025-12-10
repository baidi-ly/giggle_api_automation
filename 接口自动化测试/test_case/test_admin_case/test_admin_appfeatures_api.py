import sys
import os
from time import strftime

from pandas import DataFrame

import config
from test_case.page_api.admin.admin_appfeatures_api import AdminAppfeaturesApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest
expired_token = config.RunConfig.expired_token

@pytest.mark.Admin
@pytest.mark.AdminCourse
class TestAdminCourse:

    def setup_class(self):
        self.admin_app = AdminAppfeaturesApi()
        self.authorization = self.admin_app.get_authorization()[0]
        self.admin_auth = self.admin_app.get_admin_authorization()[0]
        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.release
    def test_admin_appfeatures_createAppFeatures_ok(self):
        """APP功能 - 增删改查验证"""
        # 新增APP功能
        featureKey = 'dibo_test_k8scluster' + self.now
        description = 'dibo_test_k8scluster_description' + self.now
        add_res = self.admin_app.createAppFeatures(self.admin_auth, featureKey, description=description)
        feature_id = add_res['data']['id']
        # 查询所有功能列表
        features_res1 = self.admin_app.getAppFeatures(self.admin_auth)
        for feature in features_res1['data']:
            if feature['id'] == feature_id:
                assert feature['description'] == description
                assert feature['key'] == featureKey
                break
        else:
            assert False, "新增APP功能后，未在功能列表中查询到新增的功能！"
        # 根据ID查询功能，验证新增APP功能正确
        detail_res1 = self.admin_app.getAppFeaturesById(self.admin_auth, feature_id)['data']
        assert detail_res1['id'] == feature_id
        assert detail_res1['description'] == description
        assert detail_res1['key'] == featureKey

        # 更新APP功能
        description_new = 'dibo_test_k8scluster_description_new' + self.now
        update_res = self.admin_app.updateAppFeatures(self.admin_auth, feature_id, rules='1,2,3', description=description_new)
        assert update_res
        # 更新APP功能后，查询所有功能列表
        features_res2 = self.admin_app.getAppFeatures(self.admin_auth)
        for feature in features_res2['data']:
            if feature['id'] == feature_id:
                assert feature['description'] == description_new
                assert feature['key'] == featureKey
                assert feature['rules'] == '1,2,3'
                break
        else:
            assert False, "更新APP功能后，未在功能列表中查询到新增的功能！"
        # 根据ID查询功能，验证更新APP功能正确
        detail_res2 = self.admin_app.getAppFeaturesById(self.admin_auth, feature_id)['data']
        assert detail_res2['id'] == feature_id
        assert detail_res2['description'] == description_new
        assert detail_res2['key'] == featureKey
        assert detail_res2['rules'] == '1,2,3'

        # 删除APP功能
        delete_res = self.admin_app.deleteAppFeatures(self.admin_auth, feature_id)
        assert delete_res['data'], "删除APP功能失败！"
        # 删除APP功能后，查询所有功能列表，验证删除成功
        features_res3 = self.admin_app.getAppFeatures(self.admin_auth)
        if features_res3['data']:
            features_ids = DataFrame(features_res3['data'])['id'].tolist()
            assert feature_id not in features_ids

    @pytest.mark.skip('功能暂时未使用，不测试')
    @pytest.mark.parametrize('ruleValue', ['10', '50', '100', '10%', '70%'])
    def test_admin_appfeatures_createAppFeaturesRules_ruleType_percent(self, ruleValue):
        """灰度规则 - 增删改查验证 - gong"""
        featureKey = 'dibo_test_k8scluster' + self.now
        ruleType = 'percent'
        add_res = self.admin_app.createAppFeaturesRules(self.admin_auth, featureKey, ruleType, ruleValue)
        assert add_res
        features_res1 = self.admin_app.getAppRulesByFeatureKey(self.admin_auth, featureKey)
        assert features_res1
        detail_res1 = self.admin_app.getAppFeaturesRulesById(self.admin_auth, rule_id)
        assert detail_res1

        update_res = self.admin_app.updateAppFeaturesRules(self.admin_auth, rule_id, ruleType, ruleValue)
        assert update_res
        features_res2 = self.admin_app.getAppRulesByFeatureKey(self.admin_auth, featureKey)
        assert features_res2
        detail_res2 = self.admin_app.getAppFeaturesRulesById(self.admin_auth, rule_id)
        assert detail_res2

        delete_res = self.admin_app.deleteAppFeaturesRules(self.admin_auth, rule_id)
        assert delete_res
        features_res3 = self.admin_app.getAppFeatures(self.admin_auth)
        assert features_res3

    @pytest.mark.skip('功能暂时未使用，不测试')
    def test_admin_appfeatures_batchDeleteAppFeatures_ok(self):
        """新增灰度规则 - 批量删除灰度规则"""
        add_res = self.admin_app.createAppFeaturesRules(self.admin_auth)
        assert add_res
        features_res1 = self.admin_app.getAppRulesByFeatureKey(self.admin_auth)
        assert features_res1
        detail_res1 = self.admin_app.batchDeleteAppFeatures(self.admin_auth)
        assert detail_res1

        features_res1 = self.admin_app.getAppRulesByFeatureKey(self.admin_auth)
        assert features_res1


