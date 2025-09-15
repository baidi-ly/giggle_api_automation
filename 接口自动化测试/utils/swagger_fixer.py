#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
修复Swagger文档中的常见问题
"""

import json
import copy
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('swagger_fixer')

def fix_swagger_doc(swagger_doc):
    """
    修复Swagger文档中的常见问题
    
    Args:
        swagger_doc: 原始Swagger文档
        
    Returns:
        dict: 修复后的Swagger文档
    """
    logger.info("开始修复Swagger文档...")
    fixed_doc = copy.deepcopy(swagger_doc)
    
    # 1. 修复formData参数中的schema问题
    for path, path_item in fixed_doc.get('paths', {}).items():
        for method, operation in path_item.items():
            if method not in ['get', 'post', 'put', 'delete', 'patch']:
                continue
                
            if 'parameters' in operation:
                fixed_params = []
                for param in operation['parameters']:
                    if param.get('in') == 'formData':
                        # 移除schema字段，直接使用type
                        if 'schema' in param:
                            param_type = param['schema'].get('type', 'string')
                            param_format = param['schema'].get('format')
                            param.pop('schema')
                            param['type'] = param_type
                            if param_format:
                                param['format'] = param_format
                    fixed_params.append(param)
                operation['parameters'] = fixed_params
    
    # 2. 确保所有参数都有type字段和required字段
    for path, path_item in fixed_doc.get('paths', {}).items():
        for method, operation in path_item.items():
            if method not in ['get', 'post', 'put', 'delete', 'patch']:
                continue
                
            if 'parameters' in operation:
                for param in operation['parameters']:
                    # 确保path参数都有required字段
                    if param.get('in') == 'path' and 'required' not in param:
                        param['required'] = True
                    
                    # 确保query参数都有type字段
                    if param.get('in') in ['path', 'query', 'header'] and 'type' not in param:
                        param['type'] = 'string'
                    
                    # 确保所有参数都有required字段
                    if 'required' not in param:
                        param['required'] = False
    
    # 3. 修复body参数格式
    for path, path_item in fixed_doc.get('paths', {}).items():
        for method, operation in path_item.items():
            if method not in ['get', 'post', 'put', 'delete', 'patch']:
                continue
                
            if 'parameters' in operation:
                for param in operation['parameters']:
                    if param.get('in') == 'body':
                        if 'schema' not in param:
                            param['schema'] = {
                                'type': 'object',
                                'properties': {}
                            }
    
    # 4. 确保所有响应都有schema
    for path, path_item in fixed_doc.get('paths', {}).items():
        for method, operation in path_item.items():
            if method not in ['get', 'post', 'put', 'delete', 'patch']:
                continue
                
            if 'responses' in operation:
                for status_code, response in operation['responses'].items():
                    if 'schema' not in response:
                        response['schema'] = {
                            'type': 'object',
                            'properties': {
                                'code': {'type': 'integer'},
                                'message': {'type': 'string'},
                                'data': {'type': 'object'}
                            }
                        }
    
    # 5. 处理循环引用问题
    # 检测并修复File类型的循环引用
    if 'definitions' in fixed_doc:
        if 'File' in fixed_doc['definitions']:
            file_def = fixed_doc['definitions']['File']
            if 'properties' in file_def:
                # 检查是否有循环引用
                for prop_name, prop in file_def['properties'].items():
                    if '$ref' in prop and prop['$ref'].endswith('/File'):
                        # 将循环引用替换为简单类型
                        logger.info(f"修复File类型中的循环引用: {prop_name}")
                        prop.pop('$ref')
                        prop['type'] = 'object'
                        prop['description'] = 'File reference (fixed)'
    
    # 6. 修复参数验证问题 - 确保所有参数都符合OpenAPI规范
    for path, path_item in fixed_doc.get('paths', {}).items():
        for method, operation in path_item.items():
            if method not in ['get', 'post', 'put', 'delete', 'patch']:
                continue
                
            if 'parameters' in operation:
                for param in operation['parameters']:
                    # 确保path参数必须有name和in字段，且required必须为true
                    if param.get('in') == 'path':
                        if 'name' not in param:
                            param['name'] = 'id'
                        # path参数必须为required
                        param['required'] = True
                        if 'type' not in param:
                            param['type'] = 'string'
                    
                    # 确保query参数有正确的格式
                    if param.get('in') == 'query':
                        if 'type' not in param:
                            param['type'] = 'string'
                        if 'required' not in param:
                            param['required'] = False
    
    logger.info("Swagger文档修复完成")
    return fixed_doc

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='修复Swagger文档中的常见问题')
    parser.add_argument('input_file', help='输入Swagger文件路径')
    parser.add_argument('--output', '-o', help='输出文件路径，默认为swagger_fixed.json')
    
    args = parser.parse_args()
    output_file = args.output or 'swagger_fixed.json'
    
    try:
        # 读取原始Swagger文档
        with open(args.input_file, 'r', encoding='utf-8') as f:
            swagger_doc = json.load(f)
        
        # 修复文档
        fixed_doc = fix_swagger_doc(swagger_doc)
        
        # 保存修复后的文档
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(fixed_doc, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Swagger文档修复完成，已保存到 {output_file}")
    except Exception as e:
        logger.error(f"处理Swagger文档时出错: {str(e)}")

if __name__ == '__main__':
    main() 