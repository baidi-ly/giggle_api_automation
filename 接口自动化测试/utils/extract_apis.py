#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
from typing import List, Dict

def load_swagger_file(file_path: str) -> dict:
    """加载swagger文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def extract_api_info(swagger_data: dict, target_apis: List[str]) -> dict:
    """从swagger数据中提取目标API信息"""
    result = {
        "swagger": swagger_data.get("swagger", "2.0"),
        "info": swagger_data.get("info", {}),
        "host": swagger_data.get("host", ""),
        "basePath": swagger_data.get("basePath", ""),
        "schemes": swagger_data.get("schemes", []),
        "paths": {},
        "definitions": {}
    }
    
    # 用于存储需要保留的定义
    required_definitions = set()
    
    # 获取所有可用的API路径
    available_paths = list(swagger_data.get("paths", {}).keys())
    print(f"Swagger文档中共有 {len(available_paths)} 个API路径")
    
    # 遍历所有目标API
    for api_path in target_apis:
        # 移除开头的斜杠
        api_path = api_path.lstrip('/')
        found = False
        
        # 在swagger的paths中查找匹配的路径
        for path, path_item in swagger_data.get("paths", {}).items():
            # 尝试多种匹配方式
            path_normalized = path.lstrip('/')
            
            # 精确匹配
            if path_normalized == api_path:
                result["paths"][path] = path_item
                found = True
                print(f"✓ 找到匹配的API: {path}")
                break
            
            # 部分匹配（包含目标路径）
            elif api_path in path_normalized:
                result["paths"][path] = path_item
                found = True
                print(f"✓ 找到部分匹配的API: {path}")
                break
        
        if not found:
            print(f"✗ 未找到匹配的API: {api_path}")
            # 显示相似的路径
            similar_paths = [p for p in available_paths if any(part in p for part in api_path.split('/') if part)]
            if similar_paths:
                print(f"  相似的路径: {similar_paths[:3]}")  # 只显示前3个

        # 收集该API使用的所有定义
        for path, path_item in result["paths"].items():
            for method in path_item.values():
                if isinstance(method, dict):
                    # 收集请求体中的定义
                    if "parameters" in method:
                        for param in method["parameters"]:
                            if "schema" in param and "$ref" in param["schema"]:
                                ref = param["schema"]["$ref"]
                                if ref.startswith("#/definitions/"):
                                    required_definitions.add(ref.split("/")[-1])

                    # 收集响应中的定义
                    if "responses" in method:
                        for response in method["responses"].values():
                            if "schema" in response and "$ref" in response["schema"]:
                                ref = response["schema"]["$ref"]
                                if ref.startswith("#/definitions/"):
                                    required_definitions.add(ref.split("/")[-1])
    
    # 只保留需要的定义
    for def_name in required_definitions:
        if def_name in swagger_data.get("definitions", {}):
            result["definitions"][def_name] = swagger_data["definitions"][def_name]
    
    return result


