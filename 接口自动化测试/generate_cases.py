#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
添加单接口用例
"""
import argparse
import json
import os
import sys

from utils.api_method_generator import generate_methods_to_api
from utils.case_generator import generate_cases
from utils.extract_apis import load_swagger_file, extract_api_info
from utils.init_swagger import init_swagger, logger
from utils.openapi_generator import OpenAPITestGenerator


if __name__ == '__main__':
    # -----------------------------------步骤1： 初始化指定的接口到swagger文件---------------------------------------
    # 目标API列表
    file_path: str = os.path.join("test_data", "api_difference.json")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"未找到差异文件: {file_path}，请先运行比较脚本生成")
    with open(file_path, "r", encoding="utf-8") as f:
        target_apis = json.load(f)

    parser = argparse.ArgumentParser(description='初始化Swagger文档')
    parser.add_argument('--url', '-u', default='https://creator.qakjukl.net/swagger-resources/v2/api-docs',
                        help='Swagger文档的URL')
    parser.add_argument('--dir', '-d', default=os.path.abspath(
        os.path.join(os.path.dirname(__file__), '../../api_test_new/data/swagger')),
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
    input_file = os.getcwd() + "/test_data/swagger_fixed.json"
    output_file = "/Users/areli/Downloads/api_test_framework/api_test_new/data/swagger/selected_apis.json"

    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # 加载swagger文件
    swagger_data = load_swagger_file(input_file)

    # 提取API信息
    extracted_data = extract_api_info(swagger_data, target_apis)

    print(f"已成功提取API信息并保存到: {output_file}")
    print(f"共提取了 {len(extracted_data['paths'])} 个API路径")
    print(f"共提取了 {len(extracted_data['definitions'])} 个相关定义")


    # -----------------------------------步骤3： 解析swagger中的接口并写入指定的文件中---------------------------------------
    parser = argparse.ArgumentParser(description='使用prance解析OpenAPI/Swagger文档并生成测试用例')
    # parser.add_argument('openapi_file', help='OpenAPI/Swagger文件路径')
    parser.add_argument('--output', '-o', default='api_test_new/testcases/generated', help='输出目录')
    parser.add_argument('--strict', '-s', action='store_true', help='是否进行严格验证')
    parser.add_argument('--recursion-limit', '-r', type=int, default=100, help='引用解析的递归限制，默认100')
    parser.add_argument('--no-resolve', '-n', action='store_true', help='不解析引用，直接使用原始规范')
    parser.add_argument('--excel-data', '-e', help='Excel测试数据文件路径')

    args = parser.parse_args()

    # 创建生成器
    openapi_file = os.getcwd() + '/test_data/swagger_fixed.json'
    generator = OpenAPITestGenerator(
        openapi_file,
        args.output,
        args.strict,
        args.recursion_limit,
        not args.no_resolve,  # 如果指定了--no-resolve，则不解析引用
        args.excel_data  # Excel测试数据文件路径
    )

    # 加载OpenAPI规范
    if not generator.load_spec():
        logger.error("加载OpenAPI规范失败")

    # 生成测试用例
    if generator.generate_test_cases():
        logger.info("测试用例生成成功")
    else:
        logger.error("测试用例生成失败")

    # -----------------------------------步骤4： 封装接口---------------------------------------
    parser = argparse.ArgumentParser(description="Swagger -> CourseApi 方法生成器")
    parser.add_argument("--module", default="course", help="目标模块目录名（如 course、book 等），默认 course")
    parser.add_argument("--include-path", dest="include_exact", action="append", help="仅生成这些精确路径的接口，可多次")
    parser.add_argument("--include-prefix", dest="include_prefix", action="append", help="仅生成以此前缀开头的接口，可多次")
    parser.add_argument("--include-regex", dest="include_regex", help="使用正则筛选路径")
    parser.add_argument("--all-paths", dest="all_paths", action="store_true", help="包含所有路径（不只限 /course）")
    parser.add_argument("--method", dest="methods", action="append", help="仅生成指定 HTTP 方法，如 --method GET，可多次")

    args = parser.parse_args()
    generate_methods_to_api(
        module=args.module,
        include_exact=['/api/course/content/detail'],
        include_prefix=args.include_prefix,
        include_regex=args.include_regex,
        only_course_related=(not args.all_paths),
        methods=args.methods,
    )

    # -----------------------------------步骤5: 生成单接口用例---------------------------------------
    generate_cases()