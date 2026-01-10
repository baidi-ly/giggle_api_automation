import datetime
import sys
import os
import random

from test_case.page_api.admin.admin_group_qr_code_api import AdminGroupQrCodeApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest


@pytest.mark.admin
class TestAdminGroupQrCode:
    """进群二维码管理测试用例"""

    def setup_class(self):
        self.admin_group_qr_code = AdminGroupQrCodeApi()
        self.authorization = self.admin_group_qr_code.get_admin_authorization()[0]

        # 用于测试的数据
        self.test_qr_code_id = None

    def setup_method(self):
        """每个测试方法开始前的准备"""
        pass

    def teardown_method(self):
        """每个测试方法结束后的清理"""
        # 清理测试数据
        if self.test_qr_code_id:
            try:
                delete_response = self.admin_group_qr_code.delete_group_qr_code(
                    self.authorization,
                    self.test_qr_code_id
                )
                # 不验证删除结果，因为测试可能已经删除了
            except Exception as e:
                pass
            finally:
                self.test_qr_code_id = None

    def test_group_qr_code_complete_workflow_business_integration(self):
        """
        进群二维码配置完整工作流业务集成验证
        业务逻辑: 验证管理员能完整管理进群二维码配置，包括创建、修改、查询、状态变更和删除的全流程
        场景: 管理员创建二维码配置后，进行修改、状态变更、查询，最后删除配置
        验证点: 各操作成功、数据准确性、状态变更正确性
        前置条件: 需要管理员权限，可以通过管理后台验证二维码配置是否正确管理
        """
        # 创建测试二维码配置（使用随机值避免冲突）
        import random
        random_suffix = str(random.randint(1000, 9999))
        create_request = {
            "countryCode": f"CN{random_suffix}",
            "channel": "WECHAT",
            "qrCodeUrl": f"https://example.com/qr/test{random_suffix}",
            "description": f"测试二维码配置{random_suffix}",
            "status": 1
        }

        # 创建二维码配置
        create_response = self.admin_group_qr_code.create_group_qr_code(self.authorization, create_request)

        # 验证创建结果
        assert create_response["code"] == 200, f"创建进群二维码配置失败: {create_response}"
        create_data = create_response["data"]
        assert create_data is not None, "创建返回数据为空"
        self.test_qr_code_id = create_data.get("id")
        assert self.test_qr_code_id is not None, "创建的配置ID为空"

        # 查询二维码配置列表，验证创建成功
        list_response = self.admin_group_qr_code.get_group_qr_code_list(
            self.authorization,
            countryCode=create_request["countryCode"],
            channel="WECHAT"
        )

        # 验证查询结果
        assert list_response["code"] == 200, f"查询进群二维码配置列表失败: {list_response}"
        list_data = list_response["data"]
        assert list_data is not None, "查询列表数据为空"

        # 验证新创建的配置在列表中
        found_config = None
        if isinstance(list_data, list):
            for config in list_data:
                if config.get("id") == self.test_qr_code_id:
                    found_config = config
                    break
        assert found_config is not None, f"未在列表中找到新创建的配置ID: {self.test_qr_code_id}"

        # 验证配置数据正确性
        assert found_config.get("countryCode") == create_request["countryCode"], "国家代码不正确"
        assert found_config.get("channel") == "WECHAT", "渠道不正确"
        assert found_config.get("qrCodeUrl") == create_request["qrCodeUrl"], "二维码URL不正确"

        # 修改二维码配置
        update_qr_url = f"https://example.com/qr/updated{random_suffix}"
        update_description = f"更新后的测试二维码配置{random_suffix}"
        update_request = {
            "id": self.test_qr_code_id,
            "countryCode": create_request["countryCode"],
            "channel": "WECHAT",
            "qrCodeUrl": update_qr_url,
            "description": update_description,
            "status": 1
        }

        # 更新配置
        update_response = self.admin_group_qr_code.update_group_qr_code(self.authorization, update_request)

        # 验证更新结果
        assert update_response["code"] == 200, f"修改进群二维码配置失败: {update_response}"

        # 再次查询验证更新成功
        list_response_after_update = self.admin_group_qr_code.get_group_qr_code_list(
            self.authorization,
            countryCode=create_request["countryCode"],
            channel="WECHAT"
        )
        assert list_response_after_update["code"] == 200, f"更新后查询失败: {list_response_after_update}"

        # 验证更新后的数据
        updated_config = None
        for config in list_response_after_update["data"]:
            if config.get("id") == self.test_qr_code_id:
                updated_config = config
                break
        assert updated_config.get("qrCodeUrl") == update_qr_url, "二维码URL更新不正确"

        # 变更配置状态
        status_request = {
            "id": self.test_qr_code_id,
            "status": "INACTIVE"  # 设置为禁用状态
        }

        # 更新状态
        status_response = self.admin_group_qr_code.update_group_qr_code_status(self.authorization, status_request)

        # 验证状态更新结果
        assert status_response["code"] == 200, f"设置进群二维码配置状态失败: {status_response}"

        # 验证状态变更成功
        list_response_after_status = self.admin_group_qr_code.get_group_qr_code_list(
            self.authorization,
            status="INACTIVE"
        )
        assert list_response_after_status["code"] == 200, f"状态变更后查询失败: {list_response_after_status}"

        # 验证状态已变更
        status_changed_config = None
        for config in list_response_after_status["data"]:
            if config.get("id") == self.test_qr_code_id:
                status_changed_config = config
                break
        assert status_changed_config.get("status") == "INACTIVE", "配置状态变更不正确"

        # 删除配置
        delete_response = self.admin_group_qr_code.delete_group_qr_code(self.authorization, self.test_qr_code_id)

        # 验证删除结果
        assert delete_response["code"] == 200, f"删除进群二维码配置失败: {delete_response}"

        # 验证删除成功 - 再次查询应该找不到
        list_response_after_delete = self.admin_group_qr_code.get_group_qr_code_list(
            self.authorization,
            countryCode=create_request["countryCode"],
            channel="WECHAT"
        )
        assert list_response_after_delete["code"] == 200, f"删除后查询失败: {list_response_after_delete}"

        # 验证配置已被删除
        deleted_config_found = False
        for config in list_response_after_delete["data"]:
            if config.get("id") == self.test_qr_code_id:
                deleted_config_found = True
                break
        assert not deleted_config_found, f"配置删除失败，仍然能找到配置ID: {self.test_qr_code_id}"

        # 清理测试数据标记
        self.test_qr_code_id = None

    def test_group_qr_code_list_filtering_business_validation(self):
        """
        进群二维码配置列表筛选业务验证
        业务逻辑: 验证管理员能根据不同条件筛选进群二维码配置列表
        场景: 管理员通过国家代码、渠道、状态等条件查询配置列表
        验证点: 筛选功能正常、返回数据准确、条件匹配正确
        前置条件: 需要有足够的测试数据，可以通过管理后台创建不同条件的配置数据
        """
        # 创建多个测试配置用于筛选测试
        test_configs = []
        for i in range(2):
            random_suffix = str(random.randint(1000, 9999))
            create_request = {
                "countryCode": f"CN{random_suffix}",
                "channel": "WECHAT",
                "qrCodeUrl": f"https://example.com/qr/filter{i}{random_suffix}",
                "description": f"筛选测试二维码配置{i}{random_suffix}",
                "status": 1
            }

            create_response = self.admin_group_qr_code.create_group_qr_code(self.authorization, create_request)
            assert create_response["code"] == 200, f"创建筛选测试配置{i}失败: {create_response}"
            config_id = create_response["data"].get("id")
            test_configs.append((config_id, create_request))

        try:
            # 使用不同筛选条件查询列表
            filter_conditions = [
                {"countryCode": test_configs[0][1]["countryCode"]},
                {"channel": "WECHAT"},
                {"status": "ACTIVE"},
                {"countryCode": test_configs[0][1]["countryCode"], "channel": "WECHAT", "status": "ACTIVE"}
            ]

            for i, condition in enumerate(filter_conditions):
                # 根据条件查询
                list_response = self.admin_group_qr_code.get_group_qr_code_list(
                    self.authorization,
                    **condition
                )

                # 验证查询结果
                assert list_response["code"] == 200, f"条件{i+1}查询进群二维码配置列表失败: {list_response}"
                list_data = list_response["data"]
                assert list_data is not None, f"条件{i+1}查询列表数据为空"

                # 验证返回的数据符合筛选条件
                if isinstance(list_data, list) and list_data:
                    for config in list_data:
                        if "countryCode" in condition:
                            assert config.get("countryCode") == condition["countryCode"], \
                                f"配置{config.get('id')}的国家代码不符合筛选条件"
                        if "channel" in condition:
                            assert config.get("channel") == condition["channel"], \
                                f"配置{config.get('id')}的渠道不符合筛选条件"
                        if "status" in condition:
                            assert config.get("status") == condition["status"], \
                                f"配置{config.get('id')}的状态不符合筛选条件"
        finally:
            # 清理筛选测试数据
            for config_id, _ in test_configs:
                try:
                    self.admin_group_qr_code.delete_group_qr_code(self.authorization, config_id)
                except Exception as e:
                    raise e
