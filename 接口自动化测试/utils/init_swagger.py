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
        response = requests.get(url, timeout=30)
        response.raise_for_status()  # 检查HTTP错误
        
        # 解析JSON响应
        swagger_doc = response.json()
        
        # 保存原始文档
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(swagger_doc, f, indent=2, ensure_ascii=False)
            
        logger.info(f"Swagger文档已下载并保存到 {output_file}")
        return True, swagger_doc
    except Exception as e:
        logger.error(f"下载Swagger文档时出错: {str(e)}")
        return False, None

def process_swagger(swagger_doc: dict, output_file: str) -> bool:
    """
    处理Swagger文档并保存
    
    Args:
        swagger_doc: Swagger文档对象
        output_file: 输出文件路径
        
    Returns:
        bool: 是否处理成功
    """
    try:
        logger.info("正在处理Swagger文档...")
        
        # 使用swagger_fixer修复文档
        fixed_doc = fix_swagger_doc(swagger_doc)
        
        # 保存修复后的文档
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(fixed_doc, f, indent=2, ensure_ascii=False)
            
        logger.info(f"Swagger文档已处理并保存到 {output_file}")
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
        fixed_file = os.path.join(swagger_dir, 'swagger_fixed.json')
        
        # 下载Swagger文档
        success, swagger_doc = download_swagger(url, raw_file)
        # if not success:
        #     return False

        new_swagger_doc = {}
        # for api in target_apis:
        #     new_swagger_doc[api] = swagger_doc[api]
        # 处理Swagger文档
        success = process_swagger(new_swagger_doc, fixed_file)
        if not success:
            return False
            
        # 如果不需要备份原始文档，则删除
        if not backup:
            os.remove(raw_file)
            logger.info(f"已删除原始文档 {raw_file}")
            
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