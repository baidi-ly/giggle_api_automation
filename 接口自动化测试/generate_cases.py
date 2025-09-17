#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
添加单接口用例
"""
import argparse
import json
import os
import sys

from utils.api_case_generator import generate_tests_for_api
from utils.api_method_generator import generate_single_method_to_api
from utils.extract_apis import load_swagger_file, extract_api_info
from utils.init_swagger import init_swagger, logger



if __name__ == '__main__':
    ''' 前置需要对装饰器进行替换'''
    # -----------------------------------步骤1： 初始化指定的接口到swagger文件---------------------------------------
    # 目标API列表
    file_path: str = os.path.join("test_data", "api_difference.json")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"未找到差异文件: {file_path}，请先运行比较脚本生成")
    with open(file_path, "r", encoding="utf-8") as f:
        target_apis = json.load(f)['apis']

    parser = argparse.ArgumentParser(description='初始化Swagger文档')
    parser.add_argument('--url', '-u', default='https://creator.qakjukl.net/swagger-resources/v2/api-docs',
                        help='Swagger文档的URL')
    parser.add_argument('--dir', '-d', default=os.path.abspath(
        os.path.join(os.path.dirname(__file__), '../../test_data/')),
                        help='Swagger文档目录')
    parser.add_argument('--no-backup', '-n', action='store_true',
                        help='不备份原始文档')

    args = parser.parse_args()

    if init_swagger(args.url, args.dir, not args.no_backup, target_apis):
        logger.info("Swagger文档初始化成功！")
    else:
        logger.error("Swagger文档初始化失败！")
        sys.exit(1)

     # -----------------------------------步骤2： 解析swagger中的接口并写入指定的文件中---------------------------------------


    # 输入和输出文件路径
    input_file = os.getcwd() + "/test_data/swagger/swagger_fixed.json"
    output_file = os.getcwd() + "/test_data/swagger/selected_apis.json"

    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # 加载swagger文件
    swagger_data = load_swagger_file(input_file)

    # 提取API信息
    extracted_data = extract_api_info(swagger_data, target_apis)

    print(f"已成功提取API信息并保存到: {output_file}")
    print(f"共提取了 {extracted_data['paths']} 个API路径")
    print(f"共提取了 {len(extracted_data['definitions'])} 个相关定义")


    # -----------------------------------步骤4： 封装接口---------------------------------------


    for api, api_info in extracted_data['paths'].items():
        for info_k, info_v in api_info.items():
            method_name = generate_single_method_to_api(
                path=api,
                http_method=info_k,
                module=api.split('/')[2],
                summary=info_v['summary'],
                force=False,
            )
            # 基于 swagger 的参数信息生成测试用例（仅 query/body/path/formData 参与测试）
            # 不校验请求头中的参数（如authorization、content-type等）
            raw_parameters = info_v.get('parameters', [])
            parameters = [p for p in raw_parameters if p.get('in') in ('query', 'body', 'path', 'formData')]
            marker = api.split('/')[2] if len(api.split('/')) > 2 else 'api'
            generate_tests_for_api(
                path=api,
                http_method=info_k,
                method_name=method_name,
                summary=info_v.get('summary', ''),
                parameters=parameters,
                marker=marker,
            )
