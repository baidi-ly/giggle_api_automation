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

    # 遍历所有目标API
    for api_path in target_apis:
        # 移除开头的斜杠
        api_path = api_path.lstrip('/')

        # 在swagger的paths中查找匹配的路径
        for path, path_item in swagger_data.get("paths", {}).items():
            if path.lstrip('/') == api_path:
                result["paths"][path] = path_item

                # 收集该API使用的所有定义
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


