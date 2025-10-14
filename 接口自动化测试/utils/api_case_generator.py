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
    marker: str = "api",
    api_difference_file: str = "test_data/api_difference.json"
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
        api_difference_file: API差异文件路径，用于检测接口变更
    
    Returns:
        生成的测试用例文件路径
    """
    # 检查接口是否在update_apis中，如果是则只校验新增参数
    try:
        from .parameter_diff_generator import ParameterDiffGenerator
        diff_generator = ParameterDiffGenerator(api_difference_file)
        
        if diff_generator.is_api_in_update_list(path, http_method):
            print(f"🔄 检测到接口 {http_method} {path} 在update_apis中，只校验新增参数")
            return diff_generator.generate_tests_for_new_parameters(
                path, http_method, method_name, summary, parameters, marker
            )
        else:
            print(f"📝 接口 {http_method} {path} 不在update_apis中，校验所有参数")
    except ImportError:
        print(f"⚠️  无法导入参数差异生成器，使用原有逻辑校验所有参数")
    except Exception as e:
        print(f"⚠️  参数差异检测出错: {e}，使用原有逻辑校验所有参数")
    
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
       - path参数：数据格式、边界值、场景异常（不包含必填测试，因为path参数在URL中无法缺失）
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

    # 处理 path 参数：数据格式、边界值、场景异常（不包含必填测试，因为path参数在URL中无法缺失）
    for param in path_params:
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
                ("emoji", "表情符号", '"😀🎉🚀"')
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
                ("below_min", "below_minimum", lower_minus_one),
                ("zero", "zero_value", zero_val),
                ("min", "minimum", lower),
                ("min_plus_one", "min_plus_one", lower_plus_one),
                ("max_minus_one", "max_minus_one", upper_minus_one),
                ("max", "maximum", upper),
                ("above_max", "above_maximum", upper_plus_one),
            ]
            seen = set()
            for key, desc, val in candidates:
                if (key, val) in seen:
                    continue
                seen.add((key, val))
                boundary_lines.append(f"            ('{key}', '{desc}', {val}, 200),")
        else:
            # 无范围: 使用32位整数极值与0
            boundary_lines = [
                "            ('min', 'minimum', -2147483648, 200),",
                "            ('zero', 'zero_value', 0, 200),",
                "            ('max', 'maximum', 2147483647, 200),",
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
            descs = ["min_length", "min_length_plus_one", "max_length_minus_one", "max_length", "max_length_plus_one"]
            for i, length in enumerate(candidates):
                if length < 0:
                    continue
                value_expr = '"' + ("a" * length) + '"'
                boundary_lines.append(f"            ('{names[i]}', '{descs[i]}', {value_expr}),")
        else:
            # 无长度要求: 最短与最长
            boundary_lines = [
                "            ('shortest', 'min_length', \"\"),",
                "            ('longest', 'max_length', \"' + 'a' * 1000 + '\"),",
            ]
    else:
        return methods
    
        methods.append(f"    @pytest.mark.release")
        methods.append(f"    @pytest.mark.parametrize(")
        methods.append(f"        'desc, value, code',")
        methods.append(f"        [")
        for line in boundary_lines:
            methods.append(line)
        methods.append(f"        ]")
        methods.append(f"    )")
        methods.append(f"    def test_{module_name}_boundary_{method_name}_{param_name}(self, desc, value, code):")
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
        
        # 添加边界值测试的断言逻辑
        methods.append("        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'")
        methods.append("        assert res['code'] == code, f\"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】\"")
        methods.append("        assert res['message'] == 'success', f\"接口返回message信息异常: 预期【success】，实际【{res['message']}】\"")
        methods.append("        assert res['data'], f\"接口返回data数据异常：{res['data']}\"")
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
    methods.append(f"        'desc, value, code',")
    methods.append(f"        [")
    methods.append(f"            ('missing',  'missing', 500),")
    methods.append(f"            ('empty', \"\", 500),")
    methods.append(f"            ('null', None, 500),")
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_required_{method_name}_{param_name}(self, desc, value, code):")
    methods.append(f'        """{summary}-必填字段测试({param_name})"""')
    
    # 获取参数类型
    param_type = target_param.get('type', 'string')
    
    # 根据参数类型生成不同的调用方式
    if param_type == 'file':
        # 文件类型参数：使用文件对象格式
        methods.append(f"        if desc == 'missing':")
        methods.append(f"            res = self.{module_name}.{method_name}(authorization=self.authorization, code=code)")
        methods.append(f"        else:")
        methods.append(f"            file = {{")
        methods.append(f"                '{param_name}': (value, open(os.getcwd() + f'/test_data/{{value}}', 'rb'))")
        methods.append(f"            }}")
        methods.append(f"            res = self.{module_name}.{method_name}(authorization=self.authorization, file=file, code=code)")
    else:
        # 其他类型参数：使用原有逻辑
        methods.append(f"        if desc == 'missing':")
        methods.append(f"            pl = {{'pop_items': '{param_name}'}}")
        methods.append(f"        else:")
        methods.append(f"            pl = {{'{param_name}': value}}")
        methods.append(f"        res = self.{module_name}.{method_name}(authorization=self.authorization, **pl, code=code)")
    
    # 添加自定义断言（根据code值进行不同断言）
    methods.append(f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"        if code == 500:")
    methods.append(f"            assert res['code'] == 500, f\"接口返回状态码异常: 预期【500】，实际【{{res['code']}}】\"")
    methods.append(f"            assert res['message'] == 'internal server error', f\"接口返回message信息异常: 预期【'internal server error'】，实际【{{res['message']}}】\"")
    methods.append(f"            assert res['data'], f\"接口返回data数据异常：预期【{{'pending'}}】，实际【{{res['data']}}】\"")
    methods.append(f"        else:")
    methods.append(f"            assert res['code'] == '${{pending}}', f\"接口返回状态码异常: 预期【{{'pending'}}】，实际【{{res['code']}}】\"")
    methods.append(f"            assert res['message'] == '${{pending}}', f\"接口返回message信息异常: 预期【{{'pending'}}】，实际【{{res['message']}}】\"")
    methods.append(f"            assert res['data'] == '${{pending}}', f\"接口返回data数据异常：预期【{{'pending'}}】，实际【{{res['data']}}】\"")
    methods.append("")
    print(f"  ✓ 已添加必填字段用例: test_{module_name}_required_{method_name}_{param_name}")
    return methods


def _generate_data_format_tests_for_param(method_name: str, query_params: List[Dict[str, Any]], body_params: List[Dict[str, Any]], module_name: str, summary: str, target_param: Dict[str, Any]) -> List[str]:
    all_params = query_params + body_params
    param_name = target_param.get('name', '')
    param_type = target_param.get('type', 'string')
    methods: List[str] = []
    
    # 根据参数类型生成不同的测试用例，现在包含4个参数：desc, value, code, code_res
    if param_type in ['integer', 'number']:
        format_tests = [
            ('string', 'abc', 200, 500),
            ('float', 12.34, 200, 500),
            ('boolean', True, 200, 500),
            ('negative', -123, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('emoji', '😀🎉🚀', 200, 500),
        ]
    elif param_type == 'boolean':
        format_tests = [
            ('string', 'abc', 200, 500),
            ('integer', 123, 200, 500),
            ('float', 12.34, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('emoji', '😀🎉🚀', 200, 500),
        ]
    else:  # string类型 - 使用丰富的测试用例
        format_tests = [
            ('integer', 123, 200, 500),
            ('float', 12.3, 200, 500),
            ('boolean', True, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('email_format', 'test@example.com', 200, 500),
            ('phone_format', '13800138000', 200, 500),
            ('date_format', '2023-12-25', 200, 500),
            ('emoji', '😀🎉🚀', 200, 500),
            ('long_string', 'a' * 1000, 200, 500),
            ('unicode', 'chinese_test', 200, 500),
            ('json_string', '{"key": "value"}', 200, 500),
            ('xml_string', '<root><item>test</item></root>', 200, 500),
            ('url_string', 'https://www.example.com', 200, 500),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 500),
        ]
    
    methods.append(f"    @pytest.mark.release")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'desc, value, code, code_res',")
    methods.append(f"        [")
    for case in format_tests:
        methods.append(f"            {case},")
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_format_{method_name}_{param_name}(self, desc, value, code, code_res):")
    methods.append(f'        """{summary}-数据格式测试({param_name})"""')
    
    # 根据参数类型生成不同的调用方式，添加code参数
    if param_type == 'file':
        # 文件类型参数：使用文件对象格式
        methods.append(f"        try:")
        methods.append(f"            file = {{")
        methods.append(f"                '{param_name}': (value, open(os.getcwd() + f'/test_data/{{value}}', 'rb'))")
        methods.append(f"            }}")
        methods.append(f"            res = self.{module_name}.{method_name}(self.authorization, file=file, code=code)")
        methods.append(f"        except Exception as res:")
        methods.append(f"            assert not code")
    else:
        # 其他类型参数：直接传递值，添加code参数
        methods.append(f"        try:")
        methods.append(f"            res = self.{module_name}.{method_name}(self.authorization, {param_name}=value, code=code)")
        methods.append(f"        except Exception as res:")
        methods.append(f"            assert not code")
    
    # 添加完整的断言逻辑
    methods.append(f"        if code and not code_res:")
    methods.append(f"            assert not res")
    methods.append(f"        elif code_res == 500:")
    methods.append(f"            assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"            assert res['code'] == 500, f\"接口返回状态码异常: 预期【500】，实际【{{res['code']}}】\"")
    methods.append(f"            assert res['message'] == 'internal server error', f\"接口返回message信息异常: 预期【'internal server error'】，实际【{{res['message']}}】\"")
    methods.append(f"            assert res['data'], f\"接口返回data数据异常：预期【{{'pending'}}】，实际【{{res['data']}}】\"")
    methods.append(f"        elif code_res == 404:")
    methods.append(f"            assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'")
    methods.append(f"            assert res['code'] == 404, f\"接口返回状态码异常: 预期【{{'pending'}}】，实际【404】\"")
    methods.append(f"            assert res['message'] == 'not found', f\"接口返回message信息异常: 预期【{{'pending'}}】，实际【'not found'】\"")
    methods.append(f"            assert res['data'] == 'not found', f\"接口返回data数据异常：预期【{{'pending'}}】，实际【'not found'】\"")
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
    
    # 根据参数类型生成相应的边界值测试用例
    boundary_lines = []
    
    if param_type in ['integer', 'number']:
        # 整数/数值类型：测试整数边界值
        boundary_lines = [
            "            ('min', -2147483648, 200),",
            "            ('zero', 0, 200),",
            "            ('max', 2147483647, 200),",
        ]
    elif param_type == 'string':
        # 字符串类型：根据minLength/maxLength生成边界值测试
        min_len = target_param.get('minLength')
        max_len = target_param.get('maxLength')
        boundary_lines: List[str] = []
        if min_len is not None and max_len is not None:
            min_len = int(min_len)
            max_len = int(max_len)
            # 生成长度: min, min+1, max-1, max, max+1
            candidates = [min_len, min_len + 1, max_len - 1, max_len, max_len + 1]
            # 保障范围合理
            names = ["min_len", "min_len_plus_one", "max_len_minus_one", "max_len", "max_len_plus_one"]
            descs = ["min_length", "min_length_plus_one", "max_length_minus_one", "max_length", "max_length_plus_one"]
            for i, length in enumerate(candidates):
                if length < 0:
                    continue
                value_expr = '"' + ("a" * length) + '"'
                boundary_lines.append(f"            ('{names[i]}', {value_expr}),")
        else:
            # 无长度要求: 最短与最长
            boundary_lines = [
                "            ('min_length', \"\", 500),",
                "            ('max_length', \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", 500),",
            ]
    elif param_type == 'boolean':
        # 布尔类型：测试布尔值边界
        boundary_lines = [
            "            ('true', True, 500),",
            "            ('false', False, 500),",
        ]
    elif param_type == 'array':
        # 数组类型：测试数组边界值
        boundary_lines = [
            "            ('empty', [], 500),",
            "            ('single', ['item'], 500),",
            "            ('multiple', ['item1', 'item2', 'item3'], 500),",
        ]
    else:
        # 其他类型：使用默认的字符串边界值
        boundary_lines = [
            "            ('empty', '', 500),",
            "            ('short', 'a', 500),",
            "            ('long', 'a' * 1000, 500),",
        ]

    methods.append(f"    @pytest.mark.release")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'desc, value, code',")
    methods.append(f"        [")
    for line in boundary_lines:
        methods.append(line)
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_boundary_{method_name}_{param_name}(self, desc, value, code):")
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
    
    # 添加边界值测试的断言逻辑
    methods.append("        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'")
    methods.append("        assert res['code'] == code, f\"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】\"")
    methods.append("        assert res['message'] == 'success', f\"接口返回message信息异常: 预期【success】，实际【{res['message']}】\"")
    methods.append("        assert res['data'], f\"接口返回data数据异常：{res['data']}\"")
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
    
    # 安全测试用例 - 按照新的格式生成
    security_tests = [
        ("sql_injection", "' OR '1'='1", 403, ''),
        ("xss_script", "<script>alert('XSS')</script>", 403, ''),
        ("xss_img", "<img src=x onerror=alert('XSS')>", 403, ''),
        ("xss_iframe", "<iframe src=javascript:alert('XSS')></iframe>", 403, ''),
        ("xml_injection", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", 403, ''),
        ("unicode_attack", "\\x00\\x01\\x02", 200, 404),
        ("crlf_injection", "test%0d%0aSet-Cookie: admin=true", 200, 404),
        ("code_injection", "eval('alert(1)')", 403, ''),
        ("regex_dos", "((a+)+)+$", 403, ''),
    ]
    
    methods: List[str] = []
    methods.append(f"    @pytest.mark.release")
    methods.append(f"    @pytest.mark.parametrize(")
    methods.append(f"        'desc, value, code, code_res',")
    methods.append(f"        [")
    for case in security_tests:
        methods.append(f"            {case},")
    methods.append(f"        ]")
    methods.append(f"    )")
    methods.append(f"    def test_{module_name}_security_{method_name}_{param_name}(self, desc, value, code, code_res):")
    methods.append(f'        """{summary}-安全测试({param_name})"""')
    methods.append(f"        res = self.{module_name}.{method_name}(self.authorization, {param_name}=value)")
    
    # 添加安全测试专用的断言逻辑
    methods.extend(_generate_security_assertions())
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


def _generate_security_assertions() -> List[str]:
    """生成安全测试专用的断言逻辑"""
    return [
        "        if code and not code_res:",
        "            assert not res",
        "        elif code_res == 500:",
        "            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'",
        "            assert res['code'] == 500, f\"接口返回状态码异常: 预期【500】，实际【{res['code']}】\"",
        "            assert res['message'] == 'internal server error', f\"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】\"",
        "        else:",
        "            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'",
        "            assert res['code'] == code_res, f\"接口返回状态码异常: 预期【{code_res}】，实际【{res['code']}】\"",
        "            assert res['message'] == 'not found', f\"接口返回message信息异常: 预期【'not found'】，实际【{res['message']}】\"",
        "            assert res['data'] == 'not found', f\"接口返回data数据异常：预期【'not found'】，实际【{res['data']}】\""
    ]


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