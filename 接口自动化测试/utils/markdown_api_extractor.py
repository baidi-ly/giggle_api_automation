#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
接口测试文档解析工具
从Markdown格式的接口测试文档中提取API信息，生成与extract_api_info相同格式的数据
"""

import re
import json
import os
from typing import Dict, List, Any, Optional


def load_markdown_file(file_path: str) -> str:
    """加载Markdown文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()


def extract_api_info_from_markdown(markdown_content: str) -> Dict[str, Any]:
    """
    从Markdown内容中提取API信息，生成与extract_api_info相同格式的数据
    
    Args:
        markdown_content: Markdown文档内容
        
    Returns:
        与extract_api_info相同格式的字典
    """
    result = {
        "swagger": "2.0",
        "info": {
            "title": "接口测试文档",
            "version": "v1.19.0",
            "description": "从Markdown文档提取的API信息"
        },
        "host": "",
        "basePath": "",
        "schemes": ["http", "https"],
        "paths": {},
        "definitions": {}
    }
    
    # 分割文档为不同的接口段落
    interface_sections = split_interface_sections(markdown_content)
    
    print(f"找到 {len(interface_sections)} 个接口段落")
    
    for section in interface_sections:
        interface_data = parse_interface_section(section)
        if interface_data:
            # 生成与swagger格式兼容的路径信息
            path = interface_data["path"]
            method = interface_data["method"].lower()
            
            if path not in result["paths"]:
                result["paths"][path] = {}
            
            # 构建swagger格式的接口信息
            swagger_method_info = {
                "summary": interface_data["name"],
                "description": interface_data["description"],
                "parameters": [],
                "responses": {
                    "200": {
                        "description": "成功",
                        "schema": {
                            "type": "object"
                        }
                    }
                },
                "tags": [interface_data.get("category", "default")]
            }
            
            # 添加参数信息
            parameters = build_parameters_from_interface_data(interface_data)
            swagger_method_info["parameters"] = parameters
            
            result["paths"][path][method] = swagger_method_info
            
            print(f"✓ 解析接口: {method.upper()} {path} - {interface_data['name']}")
    
    return result


def split_interface_sections(content: str) -> List[str]:
    """
    将文档分割为不同的接口段落
    
    Args:
        content: Markdown文档内容
        
    Returns:
        接口段落列表
    """
    sections = []
    
    # 查找所有接口标题
    # 匹配模式: #### 2.1.1 获取扭蛋活动信息
    interface_pattern = r'#### \d+\.\d+\.\d+ ([^#\n]+)'
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
        
        # 提取参数信息
        parameters = extract_parameters_from_section(section)
        interface_data["parameters"] = parameters
        
        # 提取分类信息
        category = extract_interface_category(section)
        interface_data["category"] = category
        
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
    name_match = re.search(r'#### \d+\.\d+\.\d+ (.+)', section)
    if not name_match:
        return None
    
    interface_name = name_match.group(1).strip()
    
    # 提取接口地址
    address_match = re.search(r'\*\*接口地址\*\*: `([^`]+)`', section)
    if not address_match:
        return None
    
    full_address = address_match.group(1).strip()
    
    # 解析HTTP方法和路径
    if ' ' in full_address:
        method, path = full_address.split(' ', 1)
        method = method.strip()
        path = path.strip()
    else:
        method = "GET"  # 默认方法
        path = full_address
    
    # 提取接口描述
    description_match = re.search(r'\*\*接口描述\*\*: ([^\n]+)', section)
    description = description_match.group(1).strip() if description_match else ""
    
    return {
        "name": interface_name,
        "method": method,
        "path": path,
        "description": description
    }


def extract_parameters_from_section(section: str) -> List[Dict[str, Any]]:
    """
    从接口段落中提取参数信息
    
    Args:
        section: 接口段落内容
        
    Returns:
        参数列表
    """
    parameters = []
    
    # 提取路径参数
    path_params = extract_path_parameters(section)
    print(f"✓ 提取到 {len(path_params)} 个路径参数")
    parameters.extend(path_params)
    
    # 提取请求参数
    request_params = extract_request_parameters(section)
    print(f"✓ 提取到 {len(request_params)} 个请求参数")
    parameters.extend(request_params)
    
    # 提取请求体参数
    body_params = extract_request_body_parameters(section)
    print(f"✓ 提取到 {len(body_params)} 个请求体参数")
    parameters.extend(body_params)
    
    return parameters


def extract_path_parameters(section: str) -> List[Dict[str, Any]]:
    """提取路径参数"""
    path_params = []
    
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
            
            path_params.append({
                "name": param_name,
                "in": "path",
                "type": param_type,
                "description": param_desc,
                "required": True
            })
    
    return path_params


def extract_request_parameters(section: str) -> List[Dict[str, Any]]:
    """提取请求参数（查询参数）"""
    request_params = []
    
    # 查找请求参数部分
    request_param_patterns = [
        r'- \*\*请求参数\*\*: (.+?)(?=\n- \*\*|$)',
        r'\*\*请求参数\*\*[^:]*: (.+?)(?=\n\*\*[^:]|$)',
        r'\*\*请求参数\*\*[^:]*: (.+?)(?=\n- \*\*|$)',
        r'\*\*请求参数\*\*[^:]*: (.+?)(?=\n\*\*响应示例|$)',
        r'\*\*请求参数\*\*[^:]*: (.+?)(?=\n\*\*响应|$)',
        r'\*\*请求参数\*\*[^:]*: (.+?)(?=\n\*\*|$)',
        r'\*\*请求参数\*\*[^:]*: (.+)'  # 不使用前瞻断言，手动处理
    ]
    
    request_param_match = None
    for pattern in request_param_patterns:
        request_param_match = re.search(pattern, section, re.DOTALL)
        if request_param_match:
            break
    
    if request_param_match:
        request_param_content = request_param_match.group(1)
        
        # 检查是否是JSON格式的请求体
        if '```json' in request_param_content or '{' in request_param_content:
            # 这是请求体参数，跳过
            print(f"✓ 检测到JSON格式的请求体，跳过处理")
            return request_params
        
        # 解析表格格式的参数
        lines = request_param_content.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('|') and '|' in line[1:]:
                # 表格格式: | 参数名 | 类型 | 必填 | 说明 | 示例 |
                parts = [part.strip() for part in line.split('|') if part.strip()]
                if len(parts) >= 4 and parts[0] not in ['参数名', '字段名']:
                    param_name = parts[0]
                    param_type = parts[1]
                    param_required = parts[2] in ['是', 'true', 'True', '必填']
                    param_desc = parts[3] if len(parts) > 3 else ""
                    
                    request_params.append({
                        "name": param_name,
                        "in": "query",
                        "type": param_type,
                        "description": param_desc,
                        "required": param_required
                    })
    
    return request_params


def extract_request_body_parameters(section: str) -> List[Dict[str, Any]]:
    """提取请求体参数"""
    body_params = []
    
    # 使用更直接的方法：手动查找和分割
    pos = section.find("**请求参数**")
    if pos != -1:
        print(f"✓ 找到 '**请求参数**' 在位置: {pos}")
        
        # 查找冒号
        colon_pos = section.find(":", pos)
        if colon_pos != -1:
            print(f"✓ 找到冒号在位置: {colon_pos}")
            
            # 获取冒号后的内容
            after_colon = section[colon_pos+1:]
            
            # 查找下一个**开始的位置
            next_asterisk = after_colon.find("**")
            if next_asterisk != -1:
                request_param_content = after_colon[:next_asterisk].strip()
                print(f"✓ 手动截取内容，长度: {len(request_param_content)}")
                
                # 查找JSON代码块
                json_pattern = r'```json\s*\n(.*?)\n```'
                json_match = re.search(json_pattern, request_param_content, re.DOTALL)
                
                if json_match:
                    json_content = json_match.group(1).strip()
                    try:
                        json_data = json.loads(json_content)
                        
                        # 将JSON字段转换为独立的参数
                        for field_name, field_value in json_data.items():
                            param_type = infer_parameter_type(field_value)
                            
                            body_params.append({
                                "name": field_name,
                                "in": "body",
                                "type": param_type,
                                "description": f"{field_name} 参数",
                                "required": True,
                                "schema": {
                                    "type": param_type,
                                    "example": field_value
                                }
                            })
                        
                        print(f"✓ 从JSON中提取了 {len(body_params)} 个请求体参数: {list(json_data.keys())}")
                        
                    except json.JSONDecodeError as e:
                        print(f"❌ JSON解析失败: {e}")
                else:
                    print(f"❌ 没有找到JSON代码块")
            else:
                print(f"❌ 没有找到下一个**")
        else:
            print(f"❌ 没有找到冒号")
    else:
        print(f"❌ 没有找到 '**请求参数**'")
    
    return body_params


def infer_parameter_type(value: Any) -> str:
    """推断参数类型"""
    if isinstance(value, bool):
        return "boolean"
    elif isinstance(value, int):
        return "integer"
    elif isinstance(value, float):
        return "number"
    elif isinstance(value, str):
        return "string"
    elif isinstance(value, list):
        return "array"
    elif isinstance(value, dict):
        return "object"
    else:
        return "string"


def extract_interface_category(section: str) -> str:
    """
    提取接口分类
    
    Args:
        section: 接口段落内容
        
    Returns:
        接口分类
    """
    # 查找接口分类（从上级标题获取）
    category_match = re.search(r'### \d+\.\d+ ([^#\n]+)', section)
    if category_match:
        return category_match.group(1).strip()
    
    return "default"


def build_parameters_from_interface_data(interface_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    从接口数据构建swagger格式的参数列表
    
    Args:
        interface_data: 接口数据
        
    Returns:
        swagger格式的参数列表
    """
    parameters = []
    
    # 添加路径参数
    for param in interface_data.get("parameters", []):
        if param.get("in") == "path":
            parameters.append({
                "name": param["name"],
                "in": "path",
                "type": param["type"],
                "description": param["description"],
                "required": param["required"]
            })
    
    # 添加查询参数
    query_params = [p for p in interface_data.get("parameters", []) if p.get("in") == "query"]
    if query_params:
        for param in query_params:
            parameters.append({
                "name": param["name"],
                "in": "query",
                "type": param["type"],
                "description": param["description"],
                "required": param["required"]
            })
    
    # 添加请求体参数 - 直接添加原始的body参数，不重新包装
    body_params = [p for p in interface_data.get("parameters", []) if p.get("in") == "body"]
    if body_params:
        # 直接添加每个body参数，保持原有的schema结构
        for param in body_params:
            parameters.append({
                "name": param["name"],
                "in": "body",
                "type": param["type"],
                "description": param["description"],
                "required": param.get("required", True),
                "schema": param.get("schema", {
                    "type": param["type"]
                })
            })
    
    return parameters


def extract_api_info_from_markdown_file(file_path: str) -> Dict[str, Any]:
    """
    从Markdown文件提取API信息
    
    Args:
        file_path: Markdown文件路径
        
    Returns:
        与extract_api_info相同格式的字典
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Markdown文件不存在: {file_path}")
    
    markdown_content = load_markdown_file(file_path)
    return extract_api_info_from_markdown(markdown_content)


if __name__ == "__main__":
    # 测试代码
    file_path = os.path.join("test_data", "giggle接口测试文档.md")
    
    try:
        extracted_data = extract_api_info_from_markdown_file(file_path)
        
        print(f"\n✅ 成功提取API信息")
        print(f"共提取了 {len(extracted_data['paths'])} 个API路径")
        
        # 显示提取的API路径
        if extracted_data['paths']:
            print("\n提取的API路径:")
            for path, path_info in extracted_data['paths'].items():
                for method, method_info in path_info.items():
                    print(f"  - {method.upper()} {path} - {method_info['summary']}")
        
        # 保存结果到文件
        output_file = os.path.join("test_data", "extracted_api_info.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(extracted_data, f, ensure_ascii=False, indent=2)
        
        print(f"\n结果已保存到: {output_file}")
        
    except Exception as e:
        print(f"❌ 提取失败: {e}")
