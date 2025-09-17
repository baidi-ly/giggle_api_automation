#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API测试用例生成器
基于接口参数信息生成全面的测试用例，使用@pytest.mark.parametrize进行参数化
"""

import os
import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime


def generate_tests_for_api(
    path: str,
    http_method: str,
    method_name: str,
    summary: str,
    parameters: List[Dict[str, Any]],
    marker: str = "api"
) -> str:
    """
    为指定API追加测试用例到现有测试文件
    
    Args:
        path: API路径，如 "/api/user/login"
        http_method: HTTP方法，如 "GET", "POST" 等
        method_name: 生成的方法名，如 "getUserInfo"
        summary: 接口摘要
        parameters: 参数列表，包含query和body参数
        marker: 测试标记，用于pytest筛选
    
    Returns:
        生成的测试用例文件路径
    """
    # 分离参数：只校验通过json/data/params传参的参数，以及body/path/formData参数
    # 不校验请求头中的参数（如authorization、content-type等）
    query_params = [p for p in parameters if p.get('in') == 'query']
    body_params = [p for p in parameters if p.get('in') in ['body', 'path', 'formData']]
    
    # 确定测试用例文件路径
    module_name = path.split('/')[2] if len(path.split('/')) > 2 else 'api'
    test_file_path = f"test_case/test_{module_name}_case/test_{module_name}_api.py"
    
    # 确保测试文件目录存在
    os.makedirs(os.path.dirname(test_file_path), exist_ok=True)
    
    # 生成测试用例内容
    test_methods = _generate_test_methods(
        method_name, query_params, body_params, module_name, summary
    )
    
    # 追加到现有文件
    if os.path.exists(test_file_path):
        with open(test_file_path, 'r', encoding='utf-8') as f:
            existing_content = f.read()
        
        # 纯粹追加，不修改任何现有内容
        new_content = existing_content + "\n\n" + "\n".join(test_methods) + "\n"
    else:
        # 如果文件不存在，创建基础结构
        new_content = _generate_basic_test_file(module_name, test_methods)
    
    # 写入测试文件
    with open(test_file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"已追加测试用例到文件: {test_file_path}")
    return test_file_path


def _generate_test_methods(
    method_name: str,
    query_params: List[Dict[str, Any]],
    body_params: List[Dict[str, Any]],
    module_name: str,
    summary: str = ""
) -> List[str]:
    """生成测试方法列表"""
    test_methods = []
    
    # 检查是否有参数
    has_params = bool(query_params or body_params)
    
    if has_params:
        # 有参数的情况 - 生成所有测试类别
        test_methods.extend(_generate_positive_test(method_name, query_params, body_params, module_name, summary))
        test_methods.extend(_generate_required_field_tests(method_name, query_params, body_params, module_name, summary))
        test_methods.extend(_generate_data_format_tests(method_name, query_params, body_params, module_name, summary))
        test_methods.extend(_generate_boundary_value_tests(method_name, query_params, body_params, module_name, summary))
        test_methods.extend(_generate_scenario_exception_tests(method_name, query_params, body_params, module_name, summary))
        test_methods.extend(_generate_permission_tests(method_name, query_params, body_params, module_name, summary))
        test_methods.extend(_generate_security_tests(method_name, query_params, body_params, module_name, summary))
    else:
        # 无参数的情况 - 只生成正向和权限测试
        test_methods.extend(_generate_positive_test(method_name, [], [], module_name, summary))
        test_methods.extend(_generate_permission_tests(method_name, [], [], module_name, summary))
    
    return test_methods


def _generate_basic_test_file(module_name: str, test_methods: List[str]) -> str:
    """生成基础测试文件结构"""
    imports = [
        "import pytest",
        "import time",
        "from test_case.page_api.base_api import BaseApi",
        f"from test_case.page_api.{module_name}.{module_name}_api import {module_name.capitalize()}Api",
        "from config import RunConfig",
        "",
        "base_url = RunConfig.base_url"
    ]
    
    content = "\n".join(imports) + "\n\n"
    content += f"class Test{module_name.capitalize()}Api:\n"
    content += f'    """\n    {module_name} 接口测试用例\n    """\n\n'
    content += "    @pytest.fixture(autouse=True)\n"
    content += "    def setup(self):\n"
    content += f"        self.{module_name} = {module_name.capitalize()}Api()\n"
    content += "        self.authorization = 'test_token'  # 测试用的token\n\n"
    content += "\n".join(test_methods)
    
    return content


def _generate_positive_test(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """生成正向测试用例"""
    methods = []
    
    # 构建正常参数
    normal_params = []
    if query_params:
        for param in query_params:
            param_name = param.get('name', '')
            param_type = param.get('type', 'string')
            default_value = _get_default_value(param, param_type)
            normal_params.append(f"{param_name}={default_value}")
    
    if body_params:
        for param in body_params:
            param_name = param.get('name', '')
            param_type = param.get('type', 'string')
            default_value = _get_default_value(param, param_type)
            normal_params.append(f"{param_name}={default_value}")
    
    param_str = ", ".join(normal_params) if normal_params else ""
    
    methods.append(f"    @pytest.mark.pendingRelease")
    methods.append(f"    def test_{module_name}_positive_{method_name}_ok(self):")
    methods.append(f'        """{summary}-正向用例"""')
    if param_str:
        methods.append(f"        res = self.{module_name}.{method_name}(authorization=self.authorization, {param_str})")
    else:
        methods.append(f"        res = self.{module_name}.{method_name}(authorization=self.authorization, **{{}})")
    methods.append(f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"        assert 'data' in res, f'返回结果没有data数据，response->{{res}}'")
    methods.append("")
    print(f"  ✓ 已添加正向用例: test_{module_name}_positive_{method_name}_ok")
    
    return methods


def _generate_required_field_tests(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """生成必填字段测试用例"""
    methods = []
    
    # 获取所有必填参数
    required_params = []
    for param in query_params + body_params:
        if param.get('required', False):
            required_params.append(param)
    
    if not required_params:
        return methods
    
    # 检查是否有path类型的必填参数
    has_path_params = any(p.get('in') == 'path' for p in required_params)
    
    # 根据是否有path参数决定测试用例
    if has_path_params:
        # 如果有path参数，不包含"缺失"测试用例
        test_cases = [
            ("empty", "''"),
            ("null", "'None'")
        ]
    else:
        # 如果没有path参数，包含所有测试用例
        test_cases = [
            ("missing", "''"),
            ("empty", "''"),
            ("null", "'None'")
        ]
    
    methods.append(f"    @pytest.mark.pendingRelease")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'desc, value',")
    methods.append(f"        [")
    for case in test_cases:
        methods.append(f"            {case},")
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_required_{method_name}(self, desc, value):")
    methods.append(f'        """{summary}-必填字段测试-{{desc}}"""')
    methods.append(f"        # 构建测试参数")
    
    # 构建调用参数
    call_params = []
    for param in required_params:
        param_name = param.get('name', '')
        call_params.append(f"{param_name}=value")
    
    # 添加非必填参数
    for param in query_params + body_params:
        param_name = param.get('name', '')
        param_type = param.get('type', 'string')
        if param_name not in [p.get('name', '') for p in required_params]:
            default_value = _get_default_value(param, param_type)
            call_params.append(f"{param_name}={default_value}")
    
    # 生成调用代码
    methods.append(f"        res = self.{module_name}.{method_name}(self.authorization, {', '.join(call_params)})")
    methods.append(f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"        assert 'data' in res, f'返回结果没有data数据，response->{{res}}'")
    methods.append("")
    print(f"  ✓ 已添加必填字段用例: test_{module_name}_required_{method_name}")
    
    return methods


def _generate_data_format_tests(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """生成数据格式测试用例"""
    methods = []
    
    # 只生成第一个参数的格式测试
    all_params = query_params + body_params
    if not all_params:
        return methods
    
    param = all_params[0]
    param_name = param.get('name', '')
    param_type = param.get('type', 'string')
    
    # 根据参数类型生成格式测试用例
    format_tests = []
    if param_type in ['integer', 'number']:
        format_tests = [
            ("string", "字符串", '"abc"'),
            ("float", "浮点数", "12.34"),
            ("boolean", "布尔值", "True"),
            ("array", "数组", "[1, 2, 3]"),
            ("object", "对象", '{"key": "value"}'),
            ("special_chars", "特殊字符", '"!@#$%^&*()"'),
            ("emoji", "表情符号", '"😀🎉🚀"'),
            ("long_string", "超长字符串", '"' + 'a' * 1000 + '"')
        ]
    elif param_type == 'boolean':
        format_tests = [
            ("string", "字符串", '"abc"'),
            ("integer", "整数", "123"),
            ("float", "浮点数", "12.34"),
            ("array", "数组", "[1, 2, 3]"),
            ("object", "对象", '{"key": "value"}'),
            ("special_chars", "特殊字符", '"!@#$%^&*()"'),
            ("emoji", "表情符号", '"😀🎉🚀"'),
            ("long_string", "超长字符串", '"' + 'a' * 1000 + '"')
        ]
    else:  # string类型
        format_tests = [
            ("integer", "整数", "123"),
            ("float", "浮点数", "12.34"),
            ("boolean", "布尔值", "True"),
            ("array", "数组", "[1, 2, 3]"),
            ("object", "对象", '{"key": "value"}'),
            ("special_chars", "特殊字符", '"!@#$%^&*()"'),
            ("email_format", "邮箱格式", '"test@example.com"'),
            ("phone_format", "手机号格式", '"13800138000"'),
            ("date_format", "日期格式", '"2023-12-25"'),
            ("emoji", "表情符号", '"😀🎉🚀"'),
            ("long_string", "超长字符串", '"' + 'a' * 1000 + '"'),
            ("unicode", "Unicode字符", '"中文测试"'),
            ("sql_injection", "SQL注入", '"\'; DROP TABLE users; --"'),
            ("xss", "XSS攻击", '"<script>alert(1)</script>"'),
            ("json_string", "JSON字符串", '"{\\"key\\": \\"value\\"}"'),
            ("xml_string", "XML字符串", '"<root><item>test</item></root>"'),
            ("url_string", "URL字符串", '"https://www.example.com"'),
            ("base64_string", "Base64字符串", '"SGVsbG8gV29ybGQ="')
        ]
    
    methods.append(f"    @pytest.mark.pendingRelease")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'input_param, desc, value',")
    methods.append(f"        [")
    for case in format_tests:
        methods.append(f"            {case},")
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_format_{method_name}(self, input_param, desc, value):")
    methods.append(f'        """{summary}-数据格式测试-{{desc}}"""')
    methods.append(f"        # 构建测试参数并发起请求")
    # 目标参数使用传入的 input_param/value；其余参数使用默认值
    call_args = []
    for p in all_params:
        p_name = p.get('name', '')
        p_type = p.get('type', 'string')
        if p_name == param_name:
            call_args.append(f"{p_name}=input_param")
        else:
            default_value = _get_default_value(p, p_type)
            call_args.append(f"{p_name}={default_value}")
    methods.append(f"        res = self.{module_name}.{method_name}(authorization=self.authorization, {', '.join(call_args)})")
    methods.append(f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"        assert 'data' in res, f'返回结果没有data数据，response->{{res}}'")
    methods.append("")
    print(f"  ✓ 已添加格式测试用例: test_{module_name}_format_{method_name}")
    
    return methods


def _generate_boundary_value_tests(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """生成边界值测试用例"""
    methods = []
    
    # 只生成第一个参数的边界值测试
    all_params = query_params + body_params
    if not all_params:
        return methods
    
    param = all_params[0]
    param_name = param.get('name', '')
    param_type = param.get('type', 'string')
    
    if param_type == 'integer':
        minimum = param.get('minimum')
        maximum = param.get('maximum')
        boundary_lines: List[str] = []
        if minimum is not None and maximum is not None:
            lower_minus_one = str(int(minimum) - 1)
            lower = str(int(minimum))
            lower_plus_one = str(int(minimum) + 1)
            upper_minus_one = str(int(maximum) - 1)
            upper = str(int(maximum))
            upper_plus_one = str(int(maximum) + 1)
            zero_val = "0"
            # 使用未加引号的数值字面量
            candidates = [
                ("below_min", "小于最小值", lower_minus_one),
                ("zero", "零值", zero_val),
                ("min", "最小值", lower),
                ("min_plus_one", "略大于最小值", lower_plus_one),
                ("max_minus_one", "略小于最大值", upper_minus_one),
                ("max", "最大值", upper),
                ("above_max", "大于最大值", upper_plus_one),
            ]
            seen = set()
            for key, desc, val in candidates:
                if (key, val) in seen:
                    continue
                seen.add((key, val))
                boundary_lines.append(f"            ('{key}', '{desc}', {val}),")
        else:
            # 无范围: 使用32位整数极值与0
            boundary_lines = [
                "            ('min', '最小值', -2147483648),",
                "            ('zero', '零值', 0),",
                "            ('max', '最大值', 2147483647),",
            ]
    elif param_type == 'string':
        min_len = param.get('minLength')
        max_len = param.get('maxLength')
        boundary_lines: List[str] = []
        if min_len is not None and max_len is not None:
            min_len = int(min_len)
            max_len = int(max_len)
            # 生成长度: min, min+1, max-1, max, max+1
            candidates = [min_len, min_len + 1, max_len - 1, max_len, max_len + 1]
            # 保障范围合理
            names = ["min_len", "min_len_plus_one", "max_len_minus_one", "max_len", "max_len_plus_one"]
            descs = ["最小长度", "略大于最小长度", "略小于最大长度", "最大长度", "大于最大长度"]
            for i, length in enumerate(candidates):
                if length < 0:
                    continue
                value_expr = '"' + ("a" * length) + '"'
                boundary_lines.append(f"            ('{names[i]}', '{descs[i]}', {value_expr}),")
        else:
            # 无长度要求: 最短与最长
            boundary_lines = [
                "            ('shortest', '最短长度', \"\"),",
                "            ('longest', '最长长度', \"' + 'a' * 1000 + '\"),",
            ]
    else:
        return methods
    
    methods.append(f"    @pytest.mark.pendingRelease")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'input_param, desc, value',")
    methods.append(f"        [")
    for line in boundary_lines:
        methods.append(line)
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_boundary_{method_name}(self, input_param, desc, value):")
    methods.append(f'        """{summary}-边界值测试-{{desc}}"""')
    methods.append(f"        # 构建参数并发起请求")
    call_args = []
    for p in all_params:
        p_name = p.get('name', '')
        p_type = p.get('type', 'string')
        if p_name == param_name:
            call_args.append(f"{p_name}=value")
        else:
            default_value = _get_default_value(p, p_type)
            call_args.append(f"{p_name}={default_value}")
    methods.append(f"        res = self.{module_name}.{method_name}(authorization=self.authorization, {', '.join(call_args)})")
    methods.append(f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"        assert 'data' in res, f'返回结果没有data数据，response->{{res}}'")
    methods.append("")
    print(f"  ✓ 已添加边界值用例: test_{module_name}_boundary_{method_name}")
    
    return methods


def _generate_scenario_exception_tests(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """生成场景异常测试用例"""
    methods = []
    
    # 查找可能的ID类型参数
    id_params = []
    for param in query_params + body_params:
        param_name = param.get('name', '').lower()
        if 'id' in param_name or 'rule' in param_name:
            id_params.append(param)
    
    if not id_params:
        return methods
    
    # 只生成第一个ID参数的不存在测试
    param = id_params[0]
    param_name = param.get('name', '')
    param_type = param.get('type', 'string')
    
    methods.append(f"    @pytest.mark.pendingRelease")
    methods.append(f"    def test_{module_name}_scenario_{method_name}_nonexistent_{param_name}(self):")
    methods.append(f'        """{summary}-场景异常-不存在的{param_name}"""')
    methods.append(f"        # 构建测试参数")
    methods.append(f"        test_params = {{}}")
    for p in query_params + body_params:
        p_name = p.get('name', '')
        p_type = p.get('type', 'string')
        if p_name == param_name:
            if param_type == 'integer':
                methods.append(f"        test_params['{p_name}'] = 999999")
            else:
                methods.append(f"        test_params['{p_name}'] = 'nonexistent_id'")
        else:
            default_value = _get_default_value(p, p_type)
            methods.append(f"        test_params['{p_name}'] = {default_value}")
    methods.append(f"        res = self.{module_name}.{method_name}(authorization=self.authorization, **test_params)")
    methods.append(f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"        assert 'data' in res, f'返回结果没有data数据，response->{{res}}'")
    methods.append("")
    print(f"  ✓ 已添加场景异常用例: test_{module_name}_scenario_{method_name}_nonexistent_{param_name}")
    
    return methods


def _generate_permission_tests(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """生成权限测试用例"""
    methods = []
    
    # 构建正常参数
    normal_params = []
    for param in query_params + body_params:
        param_name = param.get('name', '')
        param_type = param.get('type', 'string')
        default_value = _get_default_value(param, param_type)
        normal_params.append(f"{param_name}={default_value}")
    
    param_str = ", ".join(normal_params) if normal_params else ""
    
    # 权限测试用例
    permission_tests = [
        ("unauthorized", "未登录", "missing"),
        ("no_auth", "空token", ""),
        ("expired_token", "鉴权异常-expired_token", "expired_token"),
        ("invalid_token", "鉴权异常-invalid_token", "invalid_token"),
    ]
    
    methods.append(f"    @pytest.mark.pendingRelease")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'input_param, desc, value',")
    methods.append(f"        [")
    for case in permission_tests:
        methods.append(f"            {case},")
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_permission_{method_name}(self, input_param, desc, value):")
    methods.append(f'        """{summary}-{{desc}}"""')
    methods.append(f"        # 鉴权作为位置参数直接传入（示例期望的极简风格）")
    if param_str:
        methods.append(f"        res = self.{module_name}.{method_name}(input_param, {param_str})")
    else:
        methods.append(f"        res = self.{module_name}.{method_name}(input_param)")
    methods.append(f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"        assert 'data' in res, f'返回结果没有data数据，response->{{res}}'")
    methods.append("")
    print(f"  ✓ 已添加权限测试用例: test_{module_name}_permission_{method_name}")
    
    return methods


def _generate_security_tests(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """生成安全测试用例"""
    methods = []
    
    # 只生成第一个字符串参数的安全测试
    all_params = query_params + body_params
    string_params = [p for p in all_params if p.get('type', 'string') == 'string']
    
    if not string_params:
        return methods
    
    param = string_params[0]
    param_name = param.get('name', '')
    
    security_tests = [
        ("sql_injection", "SQL注入", "' OR 1=1 --"),
        ("xss_attack", "XSS攻击", "<script>alert('xss')</script>"),
        ("csrf_attack", "CSRF攻击", "csrf_token_here"),
    ]
    
    methods.append(f"    @pytest.mark.pendingRelease")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'test_type,test_desc,attack_value',")
    methods.append(f"        [")
    for case in security_tests:
        methods.append(f"            {case},")
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_security_{method_name}(self, test_type, test_desc, attack_value):")
    methods.append(f'        """{summary}-安全测试-{{test_desc}}"""')
    methods.append(f"        # 构建测试参数")
    methods.append(f"        test_params = {{}}")
    for p in all_params:
        p_name = p.get('name', '')
        p_type = p.get('type', 'string')
        if p_name == param_name:
            methods.append(f"        test_params['{p_name}'] = attack_value")
        else:
            default_value = _get_default_value(p, p_type)
            methods.append(f"        test_params['{p_name}'] = {default_value}")
    methods.append(f"        res = self.{module_name}.{method_name}(authorization=self.authorization, **test_params)")
    methods.append(f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"        assert 'data' in res, f'返回结果没有data数据，response->{{res}}'")
    methods.append("")
    print(f"  ✓ 已添加安全测试用例: test_{module_name}_security_{method_name}")
    
    return methods


def _get_default_value(param: Dict[str, Any], param_type: str) -> str:
    """获取参数的默认值"""
    default = param.get('default')
    
    if param_type == 'integer':
        return str(default) if isinstance(default, int) else "0"
    elif param_type == 'number':
        return str(default) if isinstance(default, (int, float)) else "0.0"
    elif param_type == 'boolean':
        return str(default).lower() if isinstance(default, bool) else "False"
    else:  # string
        return f"'{default}'" if isinstance(default, str) and default else "''"


if __name__ == "__main__":
    # 测试用例生成示例
    test_params = [
        {
            "name": "page",
            "type": "integer",
            "in": "query",
            "required": True,
            "default": 0
        },
        {
            "name": "username",
            "type": "string",
            "in": "body",
            "required": True,
            "default": "test_user"
        }
    ]
    
    generate_tests_for_api(
        path="/api/user/info",
        http_method="GET",
        method_name="getUserInfo",
        summary="获取用户信息",
        parameters=test_params,
        marker="user"
    )