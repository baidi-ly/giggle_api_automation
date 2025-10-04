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
from utils.markdown_api_extractor import extract_api_info_from_markdown_file
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
        os.path.join(os.path.dirname(__file__), 'test_data')),
                        help='Swagger文档目录')
    parser.add_argument('--no-backup', '-n', action='store_true',
                        help='不备份原始文档（默认会保留原始下载文件）')

    args = parser.parse_args()

    # 初始化swagger文档 - 不传递target_apis，保存所有API
    swagger_success = init_swagger(args.url, args.dir, not args.no_backup, [])
    if swagger_success:
        logger.info("Swagger文档初始化成功！")
    else:
        logger.warning("Swagger文档初始化失败，但继续执行...")
        # 不直接退出，继续执行后续步骤

     # -----------------------------------步骤2： 解析swagger中的接口信息---------------------------------------

    # 输入文件路径
    input_file = os.path.join("test_data", "swagger", "swagger_fixed.json")

    # 检查swagger文件是否存在
    if not os.path.exists(input_file):
        logger.error(f"Swagger文件不存在: {input_file}")
        sys.exit(1)

    # 加载swagger文件
    swagger_data = load_swagger_file(input_file)

    # 提取API信息
    extracted_data = extract_api_info(swagger_data, target_apis)

    print(f"已成功提取API信息")
    print(f"共提取了 {len(extracted_data['paths'])} 个API路径")
    print(f"共提取了 {len(extracted_data['definitions'])} 个相关定义")
    
    # 显示提取的API路径
    if extracted_data['paths']:
        print("提取的API路径:")
        for path in extracted_data['paths'].keys():
            print(f"  - {path}")
    else:
        print("警告: 没有找到匹配的API路径")
        print(f"目标API列表: {target_apis}")
        print("请检查api_difference.json中的API路径是否正确")

    # -----------------------------------步骤3： 从Markdown文档提取接口信息---------------------------------------
    
    # 从Markdown文档提取接口信息
    markdown_file = os.path.join("test_data", "接口测试文档_v1.19.0.md")
    if os.path.exists(markdown_file):
        logger.info("从Markdown文档提取接口信息...")
        try:
            markdown_extracted_data = extract_api_info_from_markdown_file(markdown_file)
            logger.info(f"从Markdown文档提取了 {len(markdown_extracted_data['paths'])} 个API路径")
            
            # 合并两个数据源的结果
            # 特殊处理：如果swagger中的接口有in=body参数，用Markdown中的body参数替换
            for path, path_info in markdown_extracted_data['paths'].items():
                # 查找匹配的swagger路径（考虑前缀差异）
                swagger_path = None
                if path in extracted_data['paths']:
                    swagger_path = path
                else:
                    # 尝试添加/api前缀
                    api_path = f"/api{path}"
                    if api_path in extracted_data['paths']:
                        swagger_path = api_path
                
                if swagger_path:
                    # 如果swagger中也有这个路径，需要特殊处理body参数
                    swagger_path_info = extracted_data['paths'][swagger_path]
                    
                    # 遍历swagger中的每个HTTP方法
                    for method, method_info in swagger_path_info.items():
                        if method in path_info:
                            # 检查swagger中是否有in=body的参数
                            swagger_parameters = method_info.get('parameters', [])
                            body_params_in_swagger = [p for p in swagger_parameters if p.get('in') == 'body']
                            
                            if body_params_in_swagger:
                                # 如果swagger中有body参数，删除它们
                                logger.info(f"删除swagger中 {method.upper()} {path} 的body参数: {[p['name'] for p in body_params_in_swagger]}")
                                
                                # 删除swagger中的body参数
                                method_info['parameters'] = [p for p in swagger_parameters if p.get('in') != 'body']
                                
                                # 从Markdown中获取body参数
                                markdown_method_info = path_info[method]
                                markdown_parameters = markdown_method_info.get('parameters', [])
                                markdown_body_params = [p for p in markdown_parameters if p.get('in') == 'body']
                                
                                if markdown_body_params:
                                    # 添加Markdown中的body参数
                                    method_info['parameters'].extend(markdown_body_params)
                                    logger.info(f"添加Markdown中 {method.upper()} {path} 的body参数: {[p['name'] for p in markdown_body_params]}")
                                else:
                                    logger.warning(f"Markdown中 {method.upper()} {path} 没有找到body参数")
                            else:
                                # 如果swagger中没有body参数，检查Markdown中是否有body参数
                                markdown_method_info = path_info[method]
                                markdown_parameters = markdown_method_info.get('parameters', [])
                                markdown_body_params = [p for p in markdown_parameters if p.get('in') == 'body']
                                
                                if markdown_body_params:
                                    # 添加Markdown中的body参数
                                    method_info['parameters'].extend(markdown_body_params)
                                    logger.info(f"添加Markdown中 {method.upper()} {path} 的body参数: {[p['name'] for p in markdown_body_params]}")
                                    
                                    # 添加其他非body参数
                                    other_params = [p for p in markdown_parameters if p.get('in') != 'body']
                                    if other_params:
                                        method_info['parameters'].extend(other_params)
                                        logger.info(f"添加Markdown中 {method.upper()} {path} 的其他参数: {[p['name'] for p in other_params]}")
                                else:
                                    # 如果没有body参数，直接合并所有参数
                                    method_info['parameters'].extend(markdown_parameters)
                                    logger.info(f"合并 {method.upper()} {path} 的所有参数")
                else:
                    # 如果swagger中没有这个接口，跳过不添加
                    logger.info(f"跳过Markdown中的接口 {path}，因为swagger中没有对应接口")
            
            print(f"合并后共提取了 {len(extracted_data['paths'])} 个API路径")
            
        except Exception as e:
            logger.error(f"从Markdown文档提取接口信息失败: {e}")
            logger.info("继续使用swagger数据...")
    else:
        logger.warning(f"Markdown文档不存在: {markdown_file}")
        logger.info("仅使用swagger数据...")

    # -----------------------------------步骤4： 封装接口---------------------------------------

    #
    # for api, api_info in extracted_data['paths'].items():
    #     for info_k, info_v in api_info.items():
    #         # 判断是否为admin接口
    #         is_admin_api = api.startswith('/admin/')
    #
    #         if is_admin_api:
    #             # admin接口的特殊处理
    #             module = api.split('/')[2] if len(api.split('/')) > 2 else 'admin'
    #             method_name = generate_single_method_to_api(
    #                 path=api,
    #                 http_method=info_k,
    #                 module=f"admin_{module}_api",  # 这会生成 test_case/page_api/admin/admin_{module}_api.py
    #                 summary=info_v['summary'],
    #                 force=True,  # 强制重新生成以使用合并后的参数
    #                 parameters=info_v.get('parameters', []),  # 传递合并后的参数
    #             )
    #             # 基于 swagger 的参数信息生成测试用例（仅 query/body/path/formData 参与测试）
    #             # 不校验请求头中的参数（如authorization、content-type等）
    #             raw_parameters = info_v.get('parameters', [])
    #             parameters = [p for p in raw_parameters if p.get('in') in ('query', 'body', 'path', 'formData')]
    #             marker = f"test_admin_{module}_api"  # test_admin_case下的test_admin_{module}_api.py文件
    #             generate_tests_for_api(
    #                 path=api,
    #                 http_method=info_k,
    #                 method_name=method_name,
    #                 summary=info_v.get('summary', ''),
    #                 parameters=parameters,
    #                 marker=marker,
    #             )
    #             logger.info(f"生成admin接口: {info_k.upper()} {api} -> test_case/page_api/admin/admin_{module}_api.py/{method_name}, 测试用例: test_admin_case/test_admin_{module}_api.py")
    #         else:
    #             # 普通接口的处理（保持原有逻辑）
    #             method_name = generate_single_method_to_api(
    #                 path=api,
    #                 http_method=info_k,
    #                 module=api.split('/')[2],
    #                 summary=info_v['summary'],
    #                 force=True,  # 强制重新生成以使用合并后的参数
    #                 parameters=info_v.get('parameters', []),  # 传递合并后的参数
    #             )
    #             # 基于 swagger 的参数信息生成测试用例（仅 query/body/path/formData 参与测试）
    #             # 不校验请求头中的参数（如authorization、content-type等）
    #             raw_parameters = info_v.get('parameters', [])
    #             parameters = [p for p in raw_parameters if p.get('in') in ('query', 'body', 'path', 'formData')]
    #             marker = api.split('/')[2] if len(api.split('/')) > 2 else 'api'
    #             generate_tests_for_api(
    #                 path=api,
    #                 http_method=info_k,
    #                 method_name=method_name,
    #                 summary=info_v.get('summary', ''),
    #                 parameters=parameters,
    #                 marker=marker,
    #             )
    #             logger.info(f"生成普通接口: {info_k.upper()} {api} -> test_case/page_api/{api.split('/')[2]}/{api.split('/')[2]}_api.py/{method_name}, 测试用例: {marker}")
