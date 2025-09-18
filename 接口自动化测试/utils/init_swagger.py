#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
初始化脚本，用于下载最新的Swagger文档并进行处理
"""

import os
import sys
import json
import argparse
import logging
import requests
from datetime import datetime

from utils.swagger_fixer import fix_swagger_doc

# 添加父目录到系统路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# 导入swagger_fixer


# 配置日志
log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data/logs'))
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(
            log_dir, 
            f'init_swagger_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        )),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('init_swagger')

def download_swagger(url: str, output_file: str) -> bool:
    """
    从指定URL下载Swagger文档
    
    Args:
        url: Swagger文档的URL
        output_file: 输出文件路径
        
    Returns:
        bool: 是否下载成功
    """
    try:
        logger.info(f"正在从 {url} 下载Swagger文档...")
        
        # 添加更完整的请求头来避免访问限制
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Referer': 'https://creator.qakjukl.net/',
            'Origin': 'https://creator.qakjukl.net',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        # 使用session来保持连接
        session = requests.Session()
        session.headers.update(headers)
        
        response = session.get(url, timeout=60, verify=False)
        response.raise_for_status()  # 检查HTTP错误
        
        # 解析JSON响应
        swagger_doc = response.json()
        
        # 保存原始文档
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(swagger_doc, f, indent=2, ensure_ascii=False)
            
        logger.info(f"Swagger文档已下载并保存到 {output_file}")
        logger.info(f"文档版本: {swagger_doc.get('info', {}).get('version', 'Unknown')}")
        logger.info(f"API路径数量: {len(swagger_doc.get('paths', {}))}")
        return True, swagger_doc
    except requests.exceptions.RequestException as e:
        logger.error(f"网络请求失败: {str(e)}")
        return False, None
    except json.JSONDecodeError as e:
        logger.error(f"JSON解析失败: {str(e)}")
        return False, None
    except Exception as e:
        logger.error(f"下载Swagger文档时出错: {str(e)}")
        return False, None

def process_swagger(swagger_doc: dict, output_file: str, target_apis: list = None) -> bool:
    """
    处理Swagger文档并保存
    
    Args:
        swagger_doc: Swagger文档对象
        output_file: 输出文件路径
        target_apis: 目标API列表，如果为None则保存所有API
        
    Returns:
        bool: 是否处理成功
    """
    try:
        logger.info("正在处理Swagger文档...")
        
        # 使用swagger_fixer修复文档
        fixed_doc = fix_swagger_doc(swagger_doc)
        
        # 如果指定了target_apis，则过滤接口
        if target_apis:
            logger.info(f"根据target_apis过滤接口，目标API数量: {len(target_apis)}")
            filtered_doc = {
                "swagger": fixed_doc.get("swagger", "2.0"),
                "info": fixed_doc.get("info", {}),
                "host": fixed_doc.get("host", ""),
                "basePath": fixed_doc.get("basePath", ""),
                "schemes": fixed_doc.get("schemes", []),
                "paths": {},
                "definitions": {}
            }
            
            # 用于存储需要保留的定义
            required_definitions = set()
            
            # 过滤目标API
            for api_path in target_apis:
                api_path = api_path.lstrip('/')
                found = False
                
                for path, path_item in fixed_doc.get("paths", {}).items():
                    path_normalized = path.lstrip('/')
                    
                    # 精确匹配或部分匹配
                    if path_normalized == api_path or api_path in path_normalized:
                        filtered_doc["paths"][path] = path_item
                        found = True
                        logger.info(f"✓ 找到匹配的API: {path}")
                        
                        # 收集该API使用的所有定义
                        for method in path_item.values():
                            if isinstance(method, dict):
                                if "parameters" in method:
                                    for param in method["parameters"]:
                                        if "schema" in param and "$ref" in param["schema"]:
                                            ref = param["schema"]["$ref"]
                                            if ref.startswith("#/definitions/"):
                                                required_definitions.add(ref.split("/")[-1])
                                
                                if "responses" in method:
                                    for response in method["responses"].values():
                                        if "schema" in response and "$ref" in response["schema"]:
                                            ref = response["schema"]["$ref"]
                                            if ref.startswith("#/definitions/"):
                                                required_definitions.add(ref.split("/")[-1])
                
                if not found:
                    logger.warning(f"✗ 未找到匹配的API: {api_path}")
            
            # 只保留需要的定义
            for def_name in required_definitions:
                if def_name in fixed_doc.get("definitions", {}):
                    filtered_doc["definitions"][def_name] = fixed_doc["definitions"][def_name]
            
            logger.info(f"过滤后保留 {len(filtered_doc['paths'])} 个API路径")
            fixed_doc = filtered_doc
        else:
            logger.info("未指定target_apis，保存所有API")
        
        # 保存修复后的文档
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(fixed_doc, f, indent=2, ensure_ascii=False)
            
        logger.info(f"Swagger文档已处理并保存到 {output_file}")
        logger.info(f"最终API路径数量: {len(fixed_doc.get('paths', {}))}")
        return True
    except Exception as e:
        logger.error(f"处理Swagger文档时出错: {str(e)}")
        return False

def init_swagger(url: str, swagger_dir: str, backup: bool = True, target_apis: list=[]) -> bool:
    """
    初始化Swagger文档
    
    Args:
        url: Swagger文档的URL
        swagger_dir: Swagger文档目录
        backup: 是否备份原始文档
        
    Returns:
        bool: 是否初始化成功
    """
    try:
        # 创建Swagger目录
        os.makedirs(swagger_dir, exist_ok=True)
        
        # 创建临时目录存放原始文档
        temp_dir = os.path.join(swagger_dir, 'temp')
        os.makedirs(temp_dir, exist_ok=True)
        
        # 定义文件路径
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        raw_file = os.path.join(temp_dir, f'swagger_raw_{timestamp}.json')
        # 确保swagger文件保存到正确的目录
        swagger_subdir = os.path.join(swagger_dir, 'swagger')
        os.makedirs(swagger_subdir, exist_ok=True)
        fixed_file = os.path.join(swagger_subdir, 'swagger_fixed.json')
        
        # 总是尝试从URL下载最新的Swagger文档
        logger.info(f"正在尝试从 {url} 下载最新的swagger文档...")
        success, swagger_doc = download_swagger(url, raw_file)
        
        if success:
            # 下载成功，处理Swagger文档
            logger.info("成功下载swagger文档，正在处理...")
            success = process_swagger(swagger_doc, fixed_file, target_apis)
            if not success:
                logger.error("处理swagger文档失败")
                return False
        else:
            # 下载失败，检查是否有现有的swagger文件作为备用
            logger.warning(f"无法从 {url} 下载swagger文档")
            if os.path.exists(fixed_file):
                logger.info(f"使用现有的swagger文件作为备用: {fixed_file}")
                return True
            else:
                logger.error("没有找到可用的swagger文件")
                return False
            
        # 如果不需要备份原始文档，则删除
        if not backup:
            try:
                os.remove(raw_file)
                logger.info(f"已删除原始文档 {raw_file}")
            except Exception as e:
                logger.warning(f"删除原始文档失败: {e}")
        else:
            logger.info(f"已保留原始文档: {raw_file}")
            
        logger.info("Swagger文档初始化成功！")
        return True
    except Exception as e:
        logger.error(f"初始化Swagger文档时出错: {str(e)}")
        return False

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='初始化Swagger文档')
    parser.add_argument('--url', '-u', default='https://creator.qakjukl.net/swagger-resources/v2/api-docs', 
                        help='Swagger文档的URL')
    parser.add_argument('--dir', '-d', default=os.path.abspath(os.path.join(os.path.dirname(__file__), '../../api_test_new/data/swagger')), 
                        help='Swagger文档目录')
    parser.add_argument('--no-backup', '-n', action='store_true', 
                        help='不备份原始文档')
    
    args = parser.parse_args()
    
    if init_swagger(args.url, args.dir, not args.no_backup):
        logger.info("Swagger文档初始化成功！")
    else:
        logger.error("Swagger文档初始化失败！")
        sys.exit(1)

if __name__ == '__main__':
    main() 