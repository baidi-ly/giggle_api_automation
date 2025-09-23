#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
接口信息提取工具
从接口变更文档_develop_vs_release_1.19.0.md中提取详细的接口信息并生成interface_info.json
"""

import os
import re
import json
from typing import Dict, List, Any, Optional
from datetime import datetime


def parse_interface_document(doc_path: str) -> Dict[str, Any]:
    """
    解析接口变更文档，提取接口信息

    Args:
        doc_path: 接口文档路径

    Returns:
        接口信息字典
    """
    interface_info = {
        "extract_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "document_version": "develop_vs_release_1.19.0",
        "interfaces": {}
    }

    if not os.path.exists(doc_path):
        print(f"警告: 接口文档文件不存在: {doc_path}")
        return interface_info

    with open(doc_path, 'r', encoding='utf-8') as f:
        content = f.read()

    print(f"开始解析接口文档: {doc_path}")
    print(f"文档长度: {len(content)} 字符")

    # 解析接口信息
    interfaces = extract_all_interfaces(content)
    interface_info["interfaces"] = interfaces

    print(f"成功提取 {len(interfaces)} 个接口")

    return interface_info


def extract_all_interfaces(content: str) -> Dict[str, Any]:
    """
    提取所有接口信息

    Args:
        content: 文档内容

    Returns:
        接口信息字典
    """
    interfaces = {}

    # 分割文档为不同的接口段落
    interface_sections = split_interface_sections(content)

    for section in interface_sections:
        interface_data = parse_interface_section(section)
        if interface_data:
            # 生成接口唯一标识
            interface_key = generate_interface_key(
                interface_data["method"],
                interface_data["path"]
            )
            interfaces[interface_key] = interface_data

    return interfaces


def split_interface_sections(content: str) -> List[str]:
    """
    将文档分割为不同的接口段落

    Args:
        content: 文档内容

    Returns:
        接口段落列表
    """
    sections = []

    # 查找所有接口标题
    # 匹配模式: #### 1.1 创建活动
    interface_pattern = r'#### \d+\.\d+ ([^#\n]+)'
    matches = list(re.finditer(interface_pattern, content))

    for i, match in enumerate(matches):
        start_pos = match.start()

        # 确定结束位置
        if i + 1 < len(matches):
            end_pos = matches[i + 1].start()
        else:
            end_pos = len(content)

        section = content[start_pos:end_pos]
        sections.append(section)

    return sections


def parse_interface_section(section: str) -> Optional[Dict[str, Any]]:
    """
    解析单个接口段落

    Args:
        section: 接口段落内容

    Returns:
        接口信息字典，如果解析失败返回None
    """
    try:
        # 提取接口基本信息
        interface_data = extract_interface_basic_info(section)
        if not interface_data:
            return None

        # 提取路径参数
        path_params = extract_path_parameters(section)
        interface_data["path_parameters"] = path_params

        # 提取请求参数
        request_params = extract_request_parameters(section)
        interface_data["request_parameters"] = request_params

        # 提取请求体信息
        request_body = extract_request_body_info(section)
        interface_data["request_body"] = request_body

        # 提取响应信息
        response = extract_response_info(section)
        interface_data["response"] = response

        # 提取功能描述
        description = extract_function_description(section)
        interface_data["description"] = description

        # 提取接口分类
        category = extract_interface_category(section)
        interface_data["category"] = category

        # 生成完整的参数列表
        all_parameters = generate_all_parameters(path_params, request_params, request_body)
        interface_data["all_parameters"] = all_parameters

        return interface_data

    except Exception as e:
        print(f"解析接口段落时出错: {e}")
        return None


def extract_interface_basic_info(section: str) -> Optional[Dict[str, Any]]:
    """
    提取接口基本信息

    Args:
        section: 接口段落内容

    Returns:
        接口基本信息字典
    """
    # 提取接口名称
    name_match = re.search(r'#### \d+\.\d+ (.+)', section)
    if not name_match:
        return None

    interface_name = name_match.group(1).strip()

    # 提取接口路径
    path_match = re.search(r'- \*\*接口路径\*\*: `([^`]+)`', section)
    if not path_match:
        return None

    full_path = path_match.group(1).strip()

    # 解析HTTP方法和路径
    if ' ' in full_path:
        method, path = full_path.split(' ', 1)
        method = method.strip()
        path = path.strip()
    else:
        method = "GET"  # 默认方法
        path = full_path

    return {
        "name": interface_name,
        "method": method,
        "path": path,
        "full_name": f"{interface_name} ({method} {path})",
        "endpoint": f"{method} {path}"
    }


def extract_path_parameters(section: str) -> Dict[str, Dict[str, Any]]:
    """
    提取路径参数

    Args:
        section: 接口段落内容

    Returns:
        路径参数信息字典
    """
    path_params = {}

    # 查找路径参数部分
    path_param_pattern = r'- \*\*路径参数\*\*: ([^#\n]+?)(?=\n- \*\*|$)'
    path_param_match = re.search(path_param_pattern, section, re.DOTALL)

    if path_param_match:
        path_param_content = path_param_match.group(1)

        # 解析路径参数
        param_pattern = r'(\w+)\s*\(([^)]+)\)\s*-\s*([^\n]+)'
        param_matches = re.findall(param_pattern, path_param_content)

        for match in param_matches:
            param_name = match[0].strip()
            param_type = match[1].strip()
            param_desc = match[2].strip()

            path_params[param_name] = {
                "name": param_name,
                "type": param_type,
                "description": param_desc,
                "location": "path",
                "required": True,
                "example": extract_example_from_description(param_desc)
            }

    return path_params


def extract_request_parameters(section: str) -> Dict[str, Dict[str, Any]]:
    """
    提取请求参数

    Args:
        section: 接口段落内容

    Returns:
        请求参数信息字典
    """
    request_params = {}

    # 查找请求参数部分 - 支持多行格式
    request_param_patterns = [
        r'- \*\*请求参数\*\*: (.+?)(?=\n- \*\*|$)',
        r'- \*\*请求参数\*\*: ([^\n]+)',
    ]

    for pattern in request_param_patterns:
        request_param_match = re.search(pattern, section, re.DOTALL)
        if request_param_match:
            request_param_content = request_param_match.group(1)

            # 解析参数列表 - 支持两种格式
            # 格式1: - paramName: type (description)
            param_pattern1 = r'- (\w+):\s*([^(]+)\s*\(([^)]+)\)'
            param_matches1 = re.findall(param_pattern1, request_param_content)

            # 格式2: - paramName: type (description) - 描述在括号外面
            if not param_matches1:
                # 尝试匹配多行格式
                lines = request_param_content.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith('- '):
                        # 移除开头的 "- "
                        line = line[2:].strip()
                        # 匹配 paramName: type (description)
                        match = re.match(r'(\w+):\s*([^(]+)\s*\(([^)]+)\)', line)
                        if match:
                            param_matches1.append(match.groups())

            for match in param_matches1:
                param_name = match[0].strip()
                param_type = match[1].strip()
                param_desc = match[2].strip()

                # 清理描述文本
                param_desc = re.sub(r'\s+', ' ', param_desc)

                # 判断是否必填
                is_required = any(keyword in param_desc.lower() for keyword in
                                  ['required', '必填', '必须', 'mandatory'])

                request_params[param_name] = {
                    "name": param_name,
                    "type": param_type,
                    "description": param_desc,
                    "location": "query",
                    "required": is_required,
                    "example": extract_example_from_description(param_desc),
                    "constraints": extract_constraints_from_description(param_desc)
                }

    return request_params


def extract_request_body_info(section: str) -> Dict[str, Any]:
    """
    提取请求体信息

    Args:
        section: 接口段落内容

    Returns:
        请求体信息
    """
    request_body = {
        "type": "",
        "description": "",
        "parameters": {}
    }

    # 查找请求参数部分（可能包含请求体）
    request_param_pattern = r'- \*\*请求参数\*\*: (.+?)(?=\n- \*\*|$)'
    request_param_match = re.search(request_param_pattern, section, re.DOTALL)

    if request_param_match:
        request_param_content = request_param_match.group(1)

        # 检查是否是请求体类型
        if 'Req' in request_param_content or 'Request' in request_param_content:
            request_body["type"] = "application/json"
            request_body["description"] = "请求体参数"

            # 解析请求体参数
            param_pattern = r'- (\w+):\s*([^(]+)\s*\(([^)]+)\)'
            param_matches = re.findall(param_pattern, request_param_content)

            for match in param_matches:
                param_name = match[0].strip()
                param_type = match[1].strip()
                param_desc = match[2].strip()

                request_body["parameters"][param_name] = {
                    "name": param_name,
                    "type": param_type,
                    "description": param_desc,
                    "location": "body",
                    "required": "必填" in param_desc or "required" in param_desc.lower(),
                    "example": extract_example_from_description(param_desc),
                    "constraints": extract_constraints_from_description(param_desc)
                }

    return request_body


def extract_response_info(section: str) -> Dict[str, Any]:
    """
    提取响应信息

    Args:
        section: 接口段落内容

    Returns:
        响应信息
    """
    response = {
        "type": "",
        "description": "",
        "schema": ""
    }

    # 查找响应部分
    response_match = re.search(r'- \*\*响应\*\*: ([^\n]+)', section)
    if response_match:
        response_content = response_match.group(1).strip()
        response["type"] = "application/json"
        response["description"] = "响应数据"
        response["schema"] = response_content

    return response


def extract_function_description(section: str) -> str:
    """
    提取功能描述

    Args:
        section: 接口段落内容

    Returns:
        功能描述
    """
    # 查找功能描述
    desc_match = re.search(r'- \*\*功能描述\*\*: ([^\n]+)', section)
    if desc_match:
        return desc_match.group(1).strip()

    return ""


def extract_interface_category(section: str) -> str:
    """
    提取接口分类

    Args:
        section: 接口段落内容

    Returns:
        接口分类
    """
    # 查找接口分类（从上级标题获取）
    category_match = re.search(r'### \d+\. ([^#\n]+)', section)
    if category_match:
        return category_match.group(1).strip()

    return ""


def extract_constraints_from_description(description: str) -> Dict[str, Any]:
    """
    从参数描述中提取约束信息

    Args:
        description: 参数描述

    Returns:
        约束信息字典
    """
    constraints = {}

    # 提取长度限制
    length_match = re.search(r'最大(\d+)字符', description)
    if length_match:
        constraints["max_length"] = int(length_match.group(1))

    # 提取格式要求
    format_match = re.search(r'格式[：:]\s*([^，,。\n]+)', description)
    if format_match:
        constraints["format"] = format_match.group(1).strip()

    # 提取默认值
    default_match = re.search(r'默认(\d+)', description)
    if default_match:
        constraints["default"] = int(default_match.group(1))

    return constraints


def extract_example_from_description(description: str) -> str:
    """
    从参数描述中提取示例值

    Args:
        description: 参数描述

    Returns:
        示例值
    """
    # 查找示例值模式
    example_patterns = [
        r'示例[：:]\s*([^，,。\n]+)',
        r'例如[：:]\s*([^，,。\n]+)',
        r'如[：:]\s*([^，,。\n]+)',
        r'([a-zA-Z0-9_]+@[a-zA-Z0-9_.]+)',  # 邮箱格式
        r'(\d{4}-\d{2}-\d{2})',  # 日期格式
        r'(\d+)',  # 数字
        r'([a-zA-Z0-9_]+)',  # 字符串
    ]

    for pattern in example_patterns:
        match = re.search(pattern, description)
        if match:
            return match.group(1)

    return ""


def generate_all_parameters(path_params: Dict, request_params: Dict, request_body: Dict) -> Dict[str, Dict[str, Any]]:
    """
    生成所有参数的统一列表

    Args:
        path_params: 路径参数
        request_params: 请求参数
        request_body: 请求体参数

    Returns:
        所有参数的统一字典
    """
    all_parameters = {}

    # 添加路径参数
    for name, param in path_params.items():
        all_parameters[name] = param

    # 添加请求参数
    for name, param in request_params.items():
        all_parameters[name] = param

    # 添加请求体参数
    if request_body.get("parameters"):
        for name, param in request_body["parameters"].items():
            all_parameters[name] = param

    return all_parameters


def generate_interface_key(method: str, path: str) -> str:
    """
    生成接口唯一标识

    Args:
        method: HTTP方法
        path: API路径

    Returns:
        接口唯一标识
    """
    # 清理路径，移除特殊字符
    clean_path = path.replace('/', '_').replace('{', '').replace('}', '').replace(':', '')
    return f"{method.upper()}_{clean_path}"


def generate_interface_info_file(
        doc_path: str = "接口变更文档_develop_vs_release_1.19.0.md",
        output_path: str = "test_data/interface_info.json"
) -> None:
    """
    生成接口信息文件

    Args:
        doc_path: 接口文档路径
        output_path: 输出文件路径
    """
    print("=" * 60)
    print("接口信息提取工具")
    print("=" * 60)

    # 解析接口文档
    interface_info = parse_interface_document(doc_path)

    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # 写入JSON文件
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(interface_info, f, ensure_ascii=False, indent=2)

    print(f"\n接口信息文件已生成: {output_path}")
    print(f"总共提取到 {len(interface_info['interfaces'])} 个接口")

    # 显示接口统计信息
    print("\n接口统计:")
    print("-" * 60)
    for key, interface in interface_info['interfaces'].items():
        path_param_count = len(interface.get('path_parameters', {}))
        request_param_count = len(interface.get('request_parameters', {}))
        body_param_count = len(interface.get('request_body', {}).get('parameters', {}))
        total_param_count = len(interface.get('all_parameters', {}))

        print(f"接口: {interface['name']}")
        print(f"  方法: {interface['method']} {interface['path']}")
        print(f"  分类: {interface.get('category', '未分类')}")
        print(f"  路径参数: {path_param_count}")
        print(f"  请求参数: {request_param_count}")
        print(f"  请求体参数: {body_param_count}")
        print(f"  总参数数: {total_param_count}")
        print(f"  响应类型: {interface.get('response', {}).get('schema', '未知')}")
        print()

    # 显示参数统计
    total_params = sum(len(interface.get('all_parameters', {})) for interface in interface_info['interfaces'].values())
    print(f"总参数数量: {total_params}")

    # 显示分类统计
    categories = {}
    for interface in interface_info['interfaces'].values():
        category = interface.get('category', '未分类')
        categories[category] = categories.get(category, 0) + 1

    print(f"\n接口分类统计:")
    for category, count in categories.items():
        print(f"  {category}: {count} 个接口")

    print("=" * 60)
    print("提取完成！")


if __name__ == "__main__":
    # 设置文件路径
    doc_path = "接口变更文档_develop_vs_release_1.19.0.md"
    output_path = "test_data/interface_info.json"

    # 生成接口信息文件
    generate_interface_info_file(doc_path, output_path)