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

def main():
    # 目标API列表
    target_apis = [
        "admin/cloudFrontUrl",
        "admin/materials/download",
        "admin/common/getFileByUrl",
        "admin/materials/{id}/files",
        "admin/course/detail",
        "admin/course/selectVersion",
        "admin/app/upload-url",
        "admin/app/version/list",
        "admin/presigned-url-for-course",
        "admin/presigned-url-for-static-bucket",
        "api/book/content",
        "api/book/{bookId}",
        "api/book/public/{bookId}",
        "api/book/bookDetail/{bookId}",
        "api/book/coverDetail/{bookId}",
        "api/materials/list",
        "api/materials/download",
        "api/private/materials/list",
        "api/private/materials/presignedUrl",
        "api/private/materials/deleteFolder",
        "api/home/latest-version",
        "api/game/resource"
    ]
    
    # 输入和输出文件路径
    input_file = "/Users/areli/Downloads/api_test_framework/api_test_new/data/swagger/swagger_fixed.json"
    output_file = "/Users/areli/Downloads/api_test_framework/api_test_new/data/swagger/selected_apis.json"
    
    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # 加载swagger文件
    swagger_data = load_swagger_file(input_file)
    
    # 提取API信息
    extracted_data = extract_api_info(swagger_data, target_apis)
    
    # 保存到新文件
    save_to_file(extracted_data, output_file)
    
    print(f"已成功提取API信息并保存到: {output_file}")
    print(f"共提取了 {len(extracted_data['paths'])} 个API路径")
    print(f"共提取了 {len(extracted_data['definitions'])} 个相关定义")

if __name__ == "__main__":
    main() 