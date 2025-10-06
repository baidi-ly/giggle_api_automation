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
    # 分离不同类型的参数
    query_params = [p for p in parameters if p.get('in') == 'query']
    body_params = [p for p in parameters if p.get('in') == 'body']
    path_params = [p for p in parameters if p.get('in') == 'path']
    file_params = [p for p in parameters if p.get('in') == 'formData' and p.get('type') == 'file']
    
    # 确定测试用例文件路径和模块名
    if "admin" in marker:
        # admin接口路径生成逻辑：/admin/user/sendEmail -> admin_user
        path_parts = path.strip('/').split('/')
        if len(path_parts) >= 2 and path_parts[0] == 'admin':
            module_name = f"admin_{path_parts[1]}"  # admin_user
        else:
            module_name = "admin"
        test_file_path = f"test_case/test_admin_case/test_{module_name}_api.py"
    else:
        module_name = path.split('/')[2] if len(path.split('/')) > 2 else 'api'
        test_file_path = f"test_case/test_{module_name}_case/test_{module_name}_api.py"
    
    # 确保测试文件目录存在
    os.makedirs(os.path.dirname(test_file_path), exist_ok=True)
    
    # 生成测试用例内容
    test_methods = _generate_test_methods(
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
        summary: str = "",
        path_params: List[Dict[str, Any]] = None,
        file_params: List[Dict[str, Any]] = None
) -> List[str]:
    """
    生成测试方法列表
    新逻辑：
    1. 一条正向用例
    2. 一条权限校验用例
    3. 根据参数类型生成不同的校验规则：
       - path参数：必填、数据格式、边界值、场景异常
       - params与body参数：必填、数据格式、边界值、场景异常、安全
       - file参数：必填、数据格式、边界值
    """
    test_methods: List[str] = []

    # 初始化参数列表
    if path_params is None:
        path_params = []
    if file_params is None:
        file_params = []

    all_params = query_params + body_params + path_params + file_params
    has_params = bool(all_params)

    # 1. 生成一条正向用例
    test_methods.extend(_generate_positive_test(method_name, query_params, body_params, module_name, summary))

    # 2. 生成一条权限校验用例
    test_methods.extend(_generate_permission_tests(method_name, query_params, body_params, module_name, summary))

    # 3. 根据参数类型生成不同的校验规则

    # 处理 path 参数：必填、数据格式、边界值、场景异常
    for param in path_params:
        test_methods.extend(
            _generate_required_field_tests_for_param(method_name, query_params, body_params, module_name, summary,
                                                     param))
        test_methods.extend(
            _generate_data_format_tests_for_param(method_name, query_params, body_params, module_name, summary, param))
        test_methods.extend(
            _generate_boundary_value_tests_for_param(method_name, query_params, body_params, module_name, summary,
                                                     param))
        test_methods.extend(
            _generate_scenario_exception_tests_for_param(method_name, query_params, body_params, module_name, summary,
                                                         param))

    # 处理 params 和 body 参数：必填、数据格式、边界值、场景异常、安全
    for param in query_params + body_params:
        test_methods.extend(
            _generate_required_field_tests_for_param(method_name, query_params, body_params, module_name, summary,
                                                     param))
        test_methods.extend(
            _generate_data_format_tests_for_param(method_name, query_params, body_params, module_name, summary, param))
        test_methods.extend(
            _generate_boundary_value_tests_for_param(method_name, query_params, body_params, module_name, summary,
                                                     param))
        test_methods.extend(
            _generate_scenario_exception_tests_for_param(method_name, query_params, body_params, module_name, summary,
                                                         param))
        test_methods.extend(
            _generate_security_tests_for_param(method_name, query_params, body_params, module_name, summary, param))

    # 处理 file 参数：必填、数据格式、边界值（不包含场景异常）
    for param in file_params:
        test_methods.extend(
            _generate_required_field_tests_for_param(method_name, query_params, body_params, module_name, summary,
                                                     param))
        test_methods.extend(
            _generate_data_format_tests_for_param(method_name, query_params, body_params, module_name, summary, param))
        test_methods.extend(
            _generate_boundary_value_tests_for_param(method_name, query_params, body_params, module_name, summary,
                                                     param))

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
    
    # 正向测试用例只传入authorization参数，其他参数使用接口中的默认值
    methods.append(f"    @pytest.mark.release")
    methods.append(f"    def test_{module_name}_positive_{method_name}_ok(self):")
    methods.append(f'        """{summary}-正向用例"""')
    methods.append(f"        res = self.{module_name}.{method_name}(self.authorization)")
    
    # 添加标准断言
    methods.extend(_generate_standard_assertions())
    methods.append("")
    print(f"  ✓ 已添加正向用例: test_{module_name}_positive_{method_name}_ok")
    
    return methods


def _generate_required_field_tests(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """为每个必填参数分别生成必填字段测试用例"""
    methods: List[str] = []
    all_params = query_params + body_params
    if not all_params:
        return methods
    
    for param in all_params:
        if not param.get('required', False):
            continue
        param_name = param.get('name', '')
        param_in = param.get('in', 'query')
        cases = [("empty", ""), ("null", "'None'")] if param_in == 'path' else [("missing", ""), ("empty", ""), ("null", "'None'")]
        methods.append(f"    @pytest.mark.release")
        methods.append(f"    @pytest.mark.parametrize(")
        methods.append(f"        'desc, value',")
        methods.append(f"        [")
        for c in cases:
            methods.append(f"            {c},")
        methods.append(f"        ]")
        methods.append(f"    )")
        methods.append(f"    def test_{module_name}_required_{method_name}_{param_name}(self, desc, value):")
        methods.append(f'        """{summary}-必填字段测试({param_name})"""')
        methods.append(f"        call_args = []")
        for p in all_params:
            p_name = p.get('name', '')
            p_type = p.get('type', 'string')
            if p_name == param_name:
                if param_in == 'path':
                    methods.append(f"        {p_name} = None if desc == 'null' else ('' if desc == 'empty' else {_get_default_value.__name__}(p, p_type))")
                    methods.append(f"        call_args.append(f'{p_name}={{ {p_name} }}')")
                else:
                    methods.append(f"        if desc == 'missing':")
                    methods.append(f"            pl_{p_name} = {{'pop_items': '{p_name}'}}")
                    methods.append(f"            {p_name} = {_get_default_value.__name__}(p, p_type)")
                    methods.append(f"        else:")
                    methods.append(f"            pl_{p_name} = {{}}")
                    methods.append(f"            {p_name} = value")
                    methods.append(f"        call_args.append(f'{p_name}={{ {p_name} }}')")
            else:
                methods.append(f"        call_args.append(f" + "'" + "{p_name}=" + "'" + f" + str({_get_default_value.__name__}(p, p_type)))")
        methods.append(f"        kwargs = {{k.split('=')[0]: eval(k.split('=')[1]) for k in call_args}}")
        if param_in != 'path':
            methods.append(f"        kwargs.update(pl_{param_name})")
        methods.append(f"        res = self.{module_name}.{method_name}(authorization=self.authorization, **kwargs)")
        
        # 添加标准断言
        methods.extend(_generate_standard_assertions())
        methods.append("")
        print(f"  ✓ 已添加必填字段用例: test_{module_name}_required_{method_name}_{param_name}")
    return methods


def _generate_data_format_tests(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """生成数据格式测试用例"""
    methods = []
    
    # 为每个参数都生成一组数据格式用例
    all_params = query_params + body_params
    if not all_params:
        return methods
    
    for param in all_params:
        param_name = param.get('name', '')
        param_type = param.get('type', 'string')
        
        # 根据参数类型生成格式测试用例
        if param_type in ['integer', 'number']:
            format_tests = [
                ("string", "字符串", '"abc"'),
                ("float", "浮点数", "12.34"),
                ("boolean", "布尔值", "True"),
                ("negative", "负数", "-123"),
                ("array", "数组", [1, 2, 3]),
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
                ("array", "数组", [1, 2, 3]),
                ("object", "对象", '{"key": "value"}'),
                ("special_chars", "特殊字符", '"!@#$%^&*()"'),
                ("emoji", "表情符号", '"😀🎉🚀"'),
                ("long_string", "超长字符串", '"' + 'a' * 1000 + '"')
            ]
        else:  # string类型
            format_tests = [
                ("integer", 123),
                ("float", 12.3),
                ("boolean", True),
                ("array", [1, 2, 3]),
                ("object", {"key": "value"}),
                ("special_chars", "!@#$%^&*()"),
                ("email_format", "test@example.com"),
                ("phone_format", "13800138000"),
                ("date_format", "2023-12-25"),
                ("emoji", "😀🎉🚀"),
                ("long_string", 'a' * 1000),
                ("unicode", "中文测试"),
                ("json_string", '{"key": "value"}'),
                ("xml_string", "<root><item>test</item></root>"),
                ("url_string", "https://www.example.com"),
                ("base64_string", "SGVsbG8gV29ybGQ=")
            ]
        
        methods.append(f"    @pytest.mark.release")
        methods.append(f"    @pytest.mark.parametrize(")
        methods.append(f"        'desc, value',")
        methods.append(f"        [")
        for case in format_tests:
            methods.append(f"            {case},")
        methods.append(f"        ]")
        methods.append(f"    )")
        methods.append(f"    def test_{module_name}_format_{method_name}_{param_name}(self, desc, value):")
        methods.append(f'        """{summary}-数据格式测试({param_name})"""')
        methods.append(f"        # 构建测试参数并发起请求")
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
        
        # 添加标准断言
        methods.extend(_generate_standard_assertions())
        methods.append("")
        print(f"  ✓ 已添加格式测试用例: test_{module_name}_format_{method_name}_{param_name}")
    
    return methods


def _generate_boundary_value_tests(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """为每个参数生成边界值测试用例"""
    methods: List[str] = []
    all_params = query_params + body_params
    if not all_params:
        return methods
    for param in all_params:
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
    
        methods.append(f"    @pytest.mark.release")
        methods.append(f"    @pytest.mark.parametrize(")
        methods.append(f"        'desc, value',")
        methods.append(f"        [")
        for line in boundary_lines:
            methods.append(line)
        methods.append(f"        ]")
        methods.append(f"    )")
        methods.append(f"    def test_{module_name}_boundary_{method_name}_{param_name}(self, desc, value):")
        methods.append(f'        """{summary}-边界值测试({param_name})"""')
        methods.append(f"        call_args = []")
        for p in all_params:
            p_name = p.get('name', '')
            p_type = p.get('type', 'string')
            if p_name == param_name:
                call_args.append(f"{p_name}=value")
            else:
                default_value = _get_default_value(p, p_type)
                call_args.append(f"{p_name}={default_value}")
        methods.append(f"        res = self.{module_name}.{method_name}(authorization=self.authorization, {', '.join(call_args)})")
        
        # 添加标准断言
        methods.extend(_generate_standard_assertions())
        methods.append("")
        print(f"  ✓ 已添加边界值用例: test_{module_name}_boundary_{method_name}_{param_name}")
    return methods


def _generate_scenario_exception_tests(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """为每个参数生成场景异常测试用例（使用通用无效值）"""
    methods: List[str] = []
    all_params = query_params + body_params
    if not all_params:
        return methods
    for param in all_params:
        param_name = param.get('name', '')
        p_type = param.get('type', 'string')
        invalid_expr = "999999999" if p_type in ['integer', 'number'] else "'INVALID_VALUE'"
        methods.append(f"    @pytest.mark.release")
        methods.append(f"    def test_{module_name}_scenario_{method_name}_invalid_{param_name}(self):")
        methods.append(f'        """{summary}-场景异常-无效的{param_name}"""')
        methods.append(f"        test_params = {{}}")
        for p in all_params:
            p_name = p.get('name', '')
            p_t = p.get('type', 'string')
            if p_name == param_name:
                methods.append(f"        test_params['{p_name}'] = {invalid_expr}")
            else:
                default_value = _get_default_value(p, p_t)
                methods.append(f"        test_params['{p_name}'] = {default_value}")
        methods.append(f"        res = self.{module_name}.{method_name}(authorization=self.authorization, **test_params)")
        
        # 添加标准断言
        methods.extend(_generate_standard_assertions())
        methods.append("")
        print(f"  ✓ 已添加场景异常用例: test_{module_name}_scenario_{method_name}_invalid_{param_name}")
    return methods


def _generate_permission_tests(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """生成权限测试用例"""
    methods = []
    
    # 权限测试用例
    permission_tests = [
        ("unauthorized", "missing"),
        ("no_auth", ""),
        ("expired_token", "expired_token"),
        ("invalid_token", "invalid_token"),
    ]
    
    methods.append(f"    @pytest.mark.release")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'desc, value',")
    methods.append(f"        [")
    for case in permission_tests:
        methods.append(f"            {case},")
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_permission_{method_name}(self, desc, value):")
    methods.append(f'        """{summary}-权限测试"""')
    methods.append(f"        # 鉴权作为位置参数直接传入（示例期望的极简风格）")
    methods.append(f"        res = self.{module_name}.{method_name}(value, code=401)")
    methods.append(f"        if res:")
    methods.append(f"            assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"            assert res['code'] == 401, f\"接口返回状态码异常: 预期【401】，实际【{{res['code']}}】\"")
    methods.append(f"            assert res['message'] == 'unauthorized', f\"接口返回message信息异常: 预期【unauthorized】，实际【{{res['message']}}】\"")
    methods.append(f"            assert res['data'], f\"接口返回data数据异常：{{res['data']}}\"")
    methods.append("")
    print(f"  ✓ 已添加权限测试用例: test_{module_name}_permission_{method_name}")
    
    return methods


def _generate_security_tests(method_name: str, query_params: List[Dict], body_params: List[Dict], module_name: str, summary: str = "") -> List[str]:
    """为每个字符串参数生成安全测试用例"""
    methods: List[str] = []
    all_params = query_params + body_params
    string_params = [p for p in all_params if p.get('type', 'string') == 'string']
    if not string_params:
        return methods
    security_tests = [
        # 移除SQL注入和XSS攻击测试项
    ]
    for param in string_params:
        param_name = param.get('name', '')
        methods.append(f"    @pytest.mark.release")
        methods.append(f"    @pytest.mark.parametrize(")
        methods.append(f"        'test_type,test_desc,attack_value',")
        methods.append(f"        [")
        for case in security_tests:
            methods.append(f"            {case},")
        methods.append(f"        ]")
        methods.append(f"    )")
        methods.append(f"    def test_{module_name}_security_{method_name}_{param_name}(self, test_type, test_desc, attack_value):")
        methods.append(f'        """{summary}-安全测试({param_name})"""')
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
        
        # 添加标准断言
        methods.extend(_generate_standard_assertions())
        methods.append("")
        print(f"  ✓ 已添加安全测试用例: test_{module_name}_security_{method_name}_{param_name}")
    return methods


# ==== Per-parameter helpers (used to enforce per-param ordering) ====

def _generate_required_field_tests_for_param(method_name: str, query_params: List[Dict[str, Any]], body_params: List[Dict[str, Any]], module_name: str, summary: str, target_param: Dict[str, Any]) -> List[str]:
    all_params = query_params + body_params
    methods: List[str] = []
    if not target_param.get('required', False):
        return methods
    param_name = target_param.get('name', '')

    methods.append(f"    @pytest.mark.release")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'desc, value',")
    methods.append(f"        [")
    methods.append(f"            ('missing',  'missing'),")
    methods.append(f"            ('empty', \"\"),")
    methods.append(f"            ('null', None),")
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_required_{method_name}_{param_name}(self, desc, value):")
    methods.append(f'        """{summary}-必填字段测试({param_name})"""')
    
    # 获取参数类型
    param_type = target_param.get('type', 'string')
    
    # 根据参数类型生成不同的调用方式
    if param_type == 'file':
        # 文件类型参数：使用文件对象格式
        methods.append(f"        if desc == 'missing':")
        methods.append(f"            res = self.{module_name}.{method_name}(authorization=self.authorization)")
        methods.append(f"        else:")
        methods.append(f"            file = {{")
        methods.append(f"                '{param_name}': (value, open(os.getcwd() + f'/test_data/{{value}}', 'rb'))")
        methods.append(f"            }}")
        methods.append(f"            res = self.{module_name}.{method_name}(authorization=self.authorization, file=file)")
    else:
        # 其他类型参数：使用原有逻辑
        methods.append(f"        if desc == 'missing':")
        methods.append(f"            pl = {{'pop_items': '{param_name}'}}")
        methods.append(f"        else:")
        methods.append(f"            pl = {{'{param_name}': value}}")
        methods.append(f"        res = self.{module_name}.{method_name}(authorization=self.authorization, **pl)")
    
    # 添加自定义断言（使用pending占位符）
    methods.append(f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"        assert res['code'] == '${{pending}}', f\"接口返回状态码异常: 预期【{{'pending'}}】，实际【{{res['code']}}】\"")
    methods.append(f"        assert res['message'] == '${{pending}}', f\"接口返回message信息异常: 预期【{{'pending'}}】，实际【{{res['message']}}】\"")
    methods.append(f"        assert res['data'] == '${{pending}}', f\"接口返回data数据异常：预期【{{'pending'}}】，实际【{{res['data']}}】\"")
    methods.append("")
    print(f"  ✓ 已添加必填字段用例: test_{module_name}_required_{method_name}_{param_name}")
    return methods


def _generate_data_format_tests_for_param(method_name: str, query_params: List[Dict[str, Any]], body_params: List[Dict[str, Any]], module_name: str, summary: str, target_param: Dict[str, Any]) -> List[str]:
    all_params = query_params + body_params
    param_name = target_param.get('name', '')
    param_type = target_param.get('type', 'string')
    methods: List[str] = []
    
    # 使用统一的测试用例格式
    format_tests = [
        ('string', 'abc'),
        ('float', 12.34),
        ('boolean', True),
        ('negative', -123),
        ('array', [1, 2, 3]),
        ('object', {'key': 'value'}),
        ('special_chars', '!@#$%^&*()'),
        ('emoji', '😀🎉🚀'),
        ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
    ]
    
    methods.append(f"    @pytest.mark.release")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'desc, value',")
    methods.append(f"        [")
    for case in format_tests:
        methods.append(f"            {case},")
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_format_{method_name}_{param_name}(self, desc, value):")
    methods.append(f'        """{summary}-数据格式测试({param_name})"""')
    
    # 根据参数类型生成不同的调用方式
    if param_type == 'file':
        # 文件类型参数：使用文件对象格式
        methods.append(f"        file = {{")
        methods.append(f"            '{param_name}': (value, open(os.getcwd() + f'/test_data/{{value}}', 'rb'))")
        methods.append(f"        }}")
        methods.append(f"        res = self.{module_name}.{method_name}(self.authorization, file=file)")
    else:
        # 其他类型参数：直接传递值
        methods.append(f"        res = self.{module_name}.{method_name}(self.authorization, {param_name}=value)")
    
    # 添加自定义断言（使用pending占位符）
    methods.append(f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"        assert res['code'] == '${{pending}}', f\"接口返回状态码异常: 预期【{{'pending'}}】，实际【{{res['code']}}】\"")
    methods.append(f"        assert res['message'] == '${{pending}}', f\"接口返回message信息异常: 预期【{{'pending'}}】，实际【{{res['message']}}】\"")
    methods.append(f"        assert res['data'] == '${{pending}}', f\"接口返回data数据异常：预期【{{'pending'}}】，实际【{{res['data']}}】\"")
    methods.append("")
    print(f"  ✓ 已添加格式测试用例: test_{module_name}_format_{method_name}_{param_name}")
    return methods


def _generate_boundary_value_tests_for_param(method_name: str, query_params: List[Dict[str, Any]],
                                             body_params: List[Dict[str, Any]], module_name: str, summary: str,
                                             target_param: Dict[str, Any]) -> List[str]:
    all_params = query_params + body_params
    param_name = target_param.get('name', '')
    param_type = target_param.get('type', 'string')
    methods: List[str] = []
    
    # 使用统一的边界值测试用例格式
    boundary_lines = [
        "            ('min', -2147483648),",
        "            ('zero', 0),",
        "            ('max', 2147483647),",
    ]

    methods.append(f"    @pytest.mark.release")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'desc, value',")
    methods.append(f"        [")
    for line in boundary_lines:
        methods.append(line)
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_boundary_{method_name}_{param_name}(self, desc, value):")
    methods.append(f'        """{summary}-边界值测试({param_name})"""')
    
    # 根据参数类型生成不同的调用方式
    if param_type == 'file':
        # 文件类型参数：使用文件对象格式
        methods.append(f"        file = {{")
        methods.append(f"            '{param_name}': (value, open(os.getcwd() + f'/test_data/{{value}}', 'rb'))")
        methods.append(f"        }}")
        methods.append(f"        res = self.{module_name}.{method_name}(self.authorization, file=file)")
    else:
        # 其他类型参数：直接传递值
        methods.append(f"        res = self.{module_name}.{method_name}(self.authorization, {param_name}=value)")
    
    # 添加自定义断言（使用pending占位符）
    methods.append(f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"        assert res['code'] == '${{pending}}', f\"接口返回状态码异常: 预期【{{'pending'}}】，实际【{{res['code']}}】\"")
    methods.append(f"        assert res['message'] == '${{pending}}', f\"接口返回message信息异常: 预期【{{'pending'}}】，实际【{{res['message']}}】\"")
    methods.append(f"        assert res['data'] == '${{pending}}', f\"接口返回data数据异常：预期【{{'pending'}}】，实际【{{res['data']}}】\"")
    methods.append("")
    print(f"  ✓ 已添加边界值用例: test_{module_name}_boundary_{method_name}_{param_name}")
    return methods


def _generate_scenario_exception_tests_for_param(method_name: str, query_params: List[Dict[str, Any]], body_params: List[Dict[str, Any]], module_name: str, summary: str, target_param: Dict[str, Any]) -> List[str]:
    all_params = query_params + body_params
    param_name = target_param.get('name', '')
    p_type = target_param.get('type', 'string')
    invalid_expr = "999999999" if p_type in ['integer', 'number'] else "'INVALID_VALUE'"
    methods: List[str] = []
    methods.append(f"    @pytest.mark.release")
    methods.append(f"    def test_{module_name}_scenario_{method_name}_invalid_{param_name}(self):")
    methods.append(f'        """{summary}-场景异常-无效的{param_name}"""')
    methods.append(f"        {param_name} = {invalid_expr}")
    methods.append(f"        res = self.{module_name}.{method_name}(self.authorization, {param_name}={param_name})")
    
    # 添加自定义断言
    methods.append(f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"        assert res['code'] == 200, f\"接口返回状态码异常: 预期【200】，实际【{{res['code']}}】\"")
    methods.append(f"        assert res['message'] == 'success', f\"接口返回message信息异常: 预期【success】，实际【{{res['message']}}】\"")
    methods.append(f"        assert res['data'], f\"接口返回data数据异常：{{res['data']}}\"")
    methods.append("")
    print(f"  ✓ 已添加场景异常用例: test_{module_name}_scenario_{method_name}_invalid_{param_name}")
    return methods


def _generate_security_tests_for_param(method_name: str, query_params: List[Dict[str, Any]], body_params: List[Dict[str, Any]], module_name: str, summary: str, target_param: Dict[str, Any]) -> List[str]:
    all_params = query_params + body_params
    if target_param.get('type', 'string') != 'string':
        return []
    param_name = target_param.get('name', '')
    
    # 安全测试用例 - 只保留核心的安全攻击方式
    security_tests = [
        ("sql_injection", "' OR '1'='1"),
        ("xss_script", "<script>alert('XSS')</script>"),
        ("xss_img", "<img src=x onerror=alert('XSS')>"),
        ("xss_iframe", "<iframe src=javascript:alert('XSS')></iframe>"),
        ("xml_injection", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"),
        ("unicode_attack", "\\x00\\x01\\x02"),
        ("crlf_injection", "test%0d%0aSet-Cookie: admin=true"),
        ("http_header_injection", "test%0d%0aX-Injected: true"),
        ("log_injection", "test%0d%0a[ERROR] Injected log entry"),
        ("code_injection", "eval('alert(1)')"),
        ("regex_dos", "((a+)+)+$"),
    ]
    
    methods: List[str] = []
    methods.append(f"    @pytest.mark.release")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'desc, value',")
    methods.append(f"        [")
    for case in security_tests:
        methods.append(f"            {case},")
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_security_{method_name}_{param_name}(self, desc, value):")
    methods.append(f'        """{summary}-安全测试({param_name})"""')
    methods.append(f"        res = self.{module_name}.{method_name}(self.authorization, {param_name}=value)")
    
    # 添加标准断言
    methods.extend(_generate_standard_assertions())
    methods.append("")
    print(f"  ✓ 已添加安全测试用例: test_{module_name}_security_{method_name}_{param_name}")
    return methods


def _get_desc_chinese_mapping(desc: str) -> str:
    """获取desc对应的中文描述"""
    mapping = {
        "unauthorized": "未登录",
        "no_auth": "无认证",
        "expired_token": "过期令牌",
        "invalid_token": "无效令牌",
        "missing": "缺失",
        "empty": "为空",
        "null": "空值",
        "string": "字符串",
        "integer": "整数",
        "float": "浮点数",
        "boolean": "布尔值",
        "array": "数组",
        "object": "对象",
        "special_chars": "特殊字符",
        "emoji": "表情符号",
        "long_string": "超长字符串",
        "unicode": "Unicode字符",
        "email_format": "邮箱格式",
        "phone_format": "手机号格式",
        "date_format": "日期格式",
        "json_string": "JSON字符串",
        "xml_string": "XML字符串",
        "url_string": "URL字符串",
        "base64_string": "Base64字符串",
        "negative": "负数",
        "min": "最小值",
        "max": "最大值",
        "zero": "零值",
        "invalid_format": "无效格式",
        "max_size": "最大尺寸"
    }
    return mapping.get(desc, desc)


def _generate_standard_assertions() -> List[str]:
    """生成标准的断言逻辑"""
    return [
        "        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'",
        "        assert res['code'] == 200, f\"接口返回状态码异常: 预期【200】，实际【{res['code']}】\"",
        "        assert res['message'] == 'success', f\"接口返回message信息异常: 预期【success】，实际【{res['message']}】\"",
        "        assert res['data'], f\"接口返回data数据异常：{res['data']}\""
    ]


def _has_default_value(param: Dict[str, Any]) -> bool:
    """判断参数是否有默认值"""
    default = param.get('default')
    return default is not None and default != ''


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