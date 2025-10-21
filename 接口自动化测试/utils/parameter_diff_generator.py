#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
参数差异用例生成器
专门为api_difference.json中的update_apis生成只校验新增参数的测试用例
"""

import os
import json
from typing import List, Dict, Any, Optional, Set
from datetime import datetime

from .api_case_generator import (
    _generate_required_field_tests_for_param,
    _generate_data_format_tests_for_param,
    _generate_boundary_value_tests_for_param,
    _generate_scenario_exception_tests_for_param,
    _generate_security_tests_for_param
)


class ParameterDiffGenerator:
    """参数差异用例生成器"""
    
    def __init__(self, api_difference_file: str = "test_data/api_difference.json"):
        self.api_difference_file = api_difference_file
        self.api_differences = self._load_api_differences()
    
    def _load_api_differences(self) -> Dict[str, Any]:
        """加载API差异文件"""
        if not os.path.exists(self.api_difference_file):
            print(f"警告: 未找到API差异文件: {self.api_difference_file}")
            return {"update_apis": []}
        
        with open(self.api_difference_file, "r", encoding="utf-8") as f:
            return json.load(f)
    
    def get_update_apis(self) -> List[Dict[str, Any]]:
        """获取需要更新的接口列表"""
        return self.api_differences.get("update_apis", [])
    
    def is_api_in_update_list(self, path: str, method: str) -> bool:
        """
        检查接口是否在update_apis列表中
        
        Args:
            path: API路径，如 "/api/user/updateProfile"
            method: HTTP方法，如 "POST"
            
        Returns:
            bool: 是否在更新列表中
        """
        update_apis = self.get_update_apis()
        for api in update_apis:
            if api.get("path") == path and api.get("method", "").upper() == method.upper():
                return True
        return False
    
    def get_added_parameters(self, path: str, method: str) -> List[Dict[str, Any]]:
        """
        获取接口的新增参数列表
        
        Args:
            path: API路径，如 "/api/user/updateProfile"
            method: HTTP方法，如 "POST"
            
        Returns:
            List[Dict]: 新增参数列表
        """
        update_apis = self.get_update_apis()
        for api in update_apis:
            if api.get("path") == path and api.get("method", "").upper() == method.upper():
                # 从changes中提取新增参数
                added_params = []
                changes = api.get("changes", [])
                for change in changes:
                    if change.get("type") == "add_parameter":
                        added_params.append(change.get("parameter", {}))
                return added_params
        
        return []
    
    def get_old_parameter_names(self, path: str, method: str) -> Set[str]:
        """
        获取接口的原始参数名称集合
        
        Args:
            path: API路径，如 "/api/user/updateProfile"
            method: HTTP方法，如 "POST"
            
        Returns:
            Set[str]: 原始参数名称集合
        """
        update_apis = self.get_update_apis()
        for api in update_apis:
            if api.get("path") == path and api.get("method", "").upper() == method.upper():
                old_params = api.get("old_parameters", [])
                return {param.get("name", "") for param in old_params}
        
        return set()
    
    def filter_new_parameters_only(self, path: str, method: str, all_parameters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        从所有参数中筛选出只包含新增参数的列表
        
        Args:
            path: API路径，如 "/api/user/updateProfile"
            method: HTTP方法，如 "POST"
            all_parameters: 所有参数列表
            
        Returns:
            List[Dict]: 只包含新增参数的列表
        """
        # 如果接口不在update_apis中，返回所有参数（保持原有逻辑）
        if not self.is_api_in_update_list(path, method):
            return all_parameters
        
        # 获取原始参数名称集合
        old_param_names = self.get_old_parameter_names(path, method)
        
        # 筛选出新增参数
        new_parameters = []
        for param in all_parameters:
            param_name = param.get("name", "")
            if param_name not in old_param_names:
                new_parameters.append(param)
        
        print(f"  📋 接口 {method} {path} 筛选结果:")
        print(f"     - 原始参数数量: {len(old_param_names)}")
        print(f"     - 总参数数量: {len(all_parameters)}")
        print(f"     - 新增参数数量: {len(new_parameters)}")
        if new_parameters:
            new_param_names = [p.get("name", "") for p in new_parameters]
            print(f"     - 新增参数: {', '.join(new_param_names)}")
        
        return new_parameters
    
    def generate_tests_for_new_parameters(
        self,
        path: str,
        http_method: str,
        method_name: str,
        summary: str,
        parameters: List[Dict[str, Any]],
        marker: str = "api"
    ) -> str:
        """
        为指定API的新增参数生成测试用例
        
        Args:
            path: API路径，如 "/api/user/updateProfile"
            http_method: HTTP方法，如 "POST"
            method_name: 生成的方法名，如 "updateProfile"
            summary: 接口摘要
            parameters: 参数列表，包含query和body参数
            marker: 测试标记，用于pytest筛选
            
        Returns:
            生成的测试用例文件路径
        """
        # 筛选出只包含新增参数的列表
        filtered_parameters = self.filter_new_parameters_only(path, http_method, parameters)
        
        # 如果没有新增参数，返回空字符串
        if not filtered_parameters:
            print(f"  ⚠️  接口 {http_method} {path} 没有新增参数，跳过测试用例生成")
            return ""
        
        # 分离不同类型的参数
        query_params = [p for p in filtered_parameters if p.get('in') == 'query']
        body_params = [p for p in filtered_parameters if p.get('in') == 'body']
        path_params = [p for p in filtered_parameters if p.get('in') == 'path']
        file_params = [p for p in filtered_parameters if p.get('in') == 'formData' and p.get('type') == 'file']
        
        # 确定测试用例文件路径和模块名
        if "admin" in marker:
            # admin接口路径生成逻辑：/admin/user/sendEmail -> admin_user
            path_parts = path.strip('/').split('/')
            if len(path_parts) >= 2 and path_parts[0] == 'admin':
                # 去掉-符号，如 author-ranking -> authorranking
                module_part = path_parts[1].replace('-', '')
                module_name = f"admin_{module_part}"  # admin_user
            else:
                module_name = "admin"
            test_file_path = f"test_case/test_admin_case/test_{module_name}_api.py"
        else:
            # 处理普通接口的模块名，将-转换为_
            path_parts = path.split('/')
            if len(path_parts) > 2:
                # 将-符号转换为_，如 study-plan -> study_plan
                module_name = path_parts[2].replace('-', '_')
            else:
                module_name = 'api'
            test_file_path = f"test_case/test_{module_name}_case/test_{module_name}_api.py"
        
        # 确保测试文件目录存在
        os.makedirs(os.path.dirname(test_file_path), exist_ok=True)
        
        # 生成测试用例内容（只针对新增参数）
        test_methods = self._generate_test_methods_for_new_params(
            method_name, query_params, body_params, module_name, summary, path_params, file_params
        )
        
        # 追加到现有文件
        if os.path.exists(test_file_path):
            with open(test_file_path, 'r', encoding='utf-8') as f:
                existing_content = f.read()
            
            # 纯粹追加，不修改任何现有内容
            new_content = existing_content + "\n\n" + "\n".join(test_methods) + "\n"
        else:
            # 如果文件不存在，创建基础结构
            new_content = self._generate_basic_test_file(module_name, test_methods)
        
        # 写入测试文件
        with open(test_file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"✅ 已为新增参数追加测试用例到文件: {test_file_path}")
        return test_file_path
    
    def _generate_test_methods_for_new_params(
        self,
        method_name: str,
        query_params: List[Dict[str, Any]],
        body_params: List[Dict[str, Any]],
        module_name: str,
        summary: str,
        path_params: List[Dict[str, Any]] = None,
        file_params: List[Dict[str, Any]] = None
    ) -> List[str]:
        """
        为新增参数生成测试方法列表
        """
        if path_params is None:
            path_params = []
        if file_params is None:
            file_params = []
            
        methods: List[str] = []
        
        # 获取所有参数（用于生成测试方法）
        all_params = query_params + body_params + path_params + file_params
        
        # 为每个新增参数生成各种类型的测试用例
        for param in all_params:
            param_name = param.get('name', '')
            print(f"  🔧 为新增参数 '{param_name}' 生成测试用例...")
            
            # 1. 必填字段测试
            required_tests = _generate_required_field_tests_for_param(
                method_name, query_params, body_params, module_name, summary, param
            )
            methods.extend(required_tests)
            
            # 2. 数据格式测试
            format_tests = _generate_data_format_tests_for_param(
                method_name, query_params, body_params, module_name, summary, param
            )
            methods.extend(format_tests)
            
            # 3. 边界值测试
            boundary_tests = _generate_boundary_value_tests_for_param(
                method_name, query_params, body_params, module_name, summary, param
            )
            methods.extend(boundary_tests)
            
            # 4. 场景异常测试
            scenario_tests = _generate_scenario_exception_tests_for_param(
                method_name, query_params, body_params, module_name, summary, param
            )
            methods.extend(scenario_tests)
            
            # 5. 安全测试（仅对string类型参数）
            security_tests = _generate_security_tests_for_param(
                method_name, query_params, body_params, module_name, summary, param
            )
            methods.extend(security_tests)
        
        return methods
    
    def _generate_basic_test_file(self, module_name: str, test_methods: List[str]) -> str:
        """生成基础测试文件结构"""
        content = f'''import pytest
import sys
import os

sys.path.append(os.getcwd())
sys.path.append("..")

from test_case.page_api.{module_name}.{module_name}_api import {module_name.title()}Api


@pytest.mark.{module_name.title()}
class Test{module_name.title()}:

    def setup_class(self):
        self.{module_name} = {module_name.title()}Api()
        self.authorization = self.{module_name}.get_authorization()

'''
        content += "\n".join(test_methods)
        return content


def generate_tests_for_api_with_diff_check(
    path: str,
    http_method: str,
    method_name: str,
    summary: str,
    parameters: List[Dict[str, Any]],
    marker: str = "api",
    api_difference_file: str = "test_data/api_difference.json"
) -> str:
    """
    为指定API生成测试用例，如果接口在update_apis中则只校验新增参数
    
    Args:
        path: API路径，如 "/api/user/updateProfile"
        http_method: HTTP方法，如 "POST"
        method_name: 生成的方法名，如 "updateProfile"
        summary: 接口摘要
        parameters: 参数列表，包含query和body参数
        marker: 测试标记，用于pytest筛选
        api_difference_file: API差异文件路径
        
    Returns:
        生成的测试用例文件路径
    """
    # 创建参数差异生成器
    diff_generator = ParameterDiffGenerator(api_difference_file)
    
    # 检查接口是否在update_apis中
    if diff_generator.is_api_in_update_list(path, http_method):
        print(f"🔄 检测到接口 {http_method} {path} 在update_apis中，只校验新增参数")
        return diff_generator.generate_tests_for_new_parameters(
            path, http_method, method_name, summary, parameters, marker
        )
    else:
        print(f"📝 接口 {http_method} {path} 不在update_apis中，校验所有参数")
        # 使用原有的生成逻辑
        from .api_case_generator import generate_tests_for_api
        return generate_tests_for_api(
            path, http_method, method_name, summary, parameters, marker
        )

