#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
使用prance库解析Swagger 2.0/OpenAPI 3.0文档并生成测试用例的脚本
支持解析引用和验证OpenAPI规范
"""

import os
import sys
import json
import argparse
import logging
import re
from datetime import datetime
from prance import ResolvingParser, BaseParser
import yaml
import random
import string
from typing import Dict, List, Any, Tuple, Optional, Union

# 添加父目录到系统路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# 导入Excel数据提供者


# 配置日志
log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data/logs'))
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(
            log_dir, 
            f'openapi_generator_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        )),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('openapi_generator')

class OpenAPITestGenerator:
    """OpenAPI测试用例生成器"""
    
    def __init__(self, openapi_file: str, output_dir: str, strict_validation: bool = False, 
                 recursion_limit: int = 10, resolve_refs: bool = True, excel_data: str = None):
        """初始化生成器

        Args:
            openapi_file: OpenAPI/Swagger文件路径
            output_dir: 输出目录
            strict_validation: 是否进行严格验证
            recursion_limit: 引用解析的递归限制
            resolve_refs: 是否解析引用
            excel_data: Excel测试数据文件路径
        """
        self.openapi_file = openapi_file
        self.output_dir = output_dir
        self.strict_validation = strict_validation
        self.recursion_limit = recursion_limit
        self.resolve_refs = resolve_refs
        self.excel_data = excel_data
        self.spec = None
        self.version = None
        
        # 初始化Excel数据提供者
        self.data_provider = None
        if self.excel_data and os.path.exists(self.excel_data):
            self.data_provider = ExcelDataProvider(self.excel_data)
            logger.info(f"已加载Excel测试数据文件: {self.excel_data}")
        elif self.excel_data:
            logger.warning(f"指定的Excel文件不存在: {self.excel_data}")
        
    def load_spec(self) -> bool:
        """加载并解析OpenAPI规范文件
        
        Returns:
            bool: 是否成功加载
        """
        try:
            # 选择解析器
            if self.resolve_refs:
                # 使用解析引用的解析器
                logger.info("使用ResolvingParser解析引用")
                parser = ResolvingParser(self.openapi_file, 
                                        strict=self.strict_validation,
                                        recursion_limit=self.recursion_limit)
            else:
                # 使用不解析引用的基础解析器
                logger.info("使用BaseParser，不解析引用")
                parser = BaseParser(self.openapi_file, 
                                   strict=self.strict_validation)
                
            self.spec = parser.specification
            
            # 获取OpenAPI版本
            if 'swagger' in self.spec:
                self.version = self.spec['swagger']
                logger.info(f"检测到Swagger {self.version}规范")
            elif 'openapi' in self.spec:
                self.version = self.spec['openapi']
                logger.info(f"检测到OpenAPI {self.version}规范")
            else:
                logger.error("无法确定OpenAPI/Swagger版本")
                return False
                
            return True
        except Exception as e:
            logger.error(f"加载OpenAPI规范时出错: {str(e)}")
            return False
    
    def _generate_example_value(self, schema: Dict, property_name: str = None, api_name: str = None, depth: int = 0) -> Any:
        """根据JSON Schema生成示例值
        
        Args:
            schema: JSON Schema定义
            property_name: 属性名称，用于生成更有意义的示例值
            api_name: API名称，用于从Excel获取测试数据
            depth: 递归深度，防止无限递归
            
        Returns:
            生成的示例值
        """
        # 防止递归过深
        if depth > 5:
            logger.warning(f"递归深度过深({depth})，停止生成示例值: {property_name}")
            return "..." if schema.get('type') == 'string' else {}
        # 如果有Excel数据提供者且提供了API名称和属性名，尝试从Excel获取测试数据
        if self.data_provider and api_name and property_name:
            # 从Excel获取参数值
            excel_value = self.data_provider.get_param_value(api_name, property_name)
            logger.debug(f"尝试从Excel获取: API[{api_name}] 参数[{property_name}] = {excel_value}")
            if excel_value is not None and excel_value != '':
                logger.info(f"从Excel获取测试数据: API[{api_name}] 参数[{property_name}] = {excel_value}")
                return excel_value
            elif excel_value == '' or excel_value is None:
                # 如果Excel中的值是空字符串或None，返回None，表示不包含这个字段
                logger.debug(f"Excel中参数[{property_name}]为空，跳过该字段")
                return None
                
            # 检查是否是引用schema
            if '$ref' in schema:
                ref = schema['$ref']
                ref_name = ref.split('/')[-1]
                
                # 尝试获取整个schema对象
                schema_body_value = self.data_provider.get_param_value(api_name, f"{ref_name}_body")
                if schema_body_value is not None:
                    logger.info(f"从Excel获取引用schema: API[{api_name}] 参数[{ref_name}_body] = {schema_body_value}")
                    return schema_body_value
        
        # 首先检查schema中是否已有示例值
        if 'example' in schema:
            return schema['example']
            
        # 处理$ref引用
        if '$ref' in schema:
            ref = schema['$ref']
            ref_name = ref.split('/')[-1]
            
            # 如果有Excel数据提供者且提供了API名称，尝试从Excel获取引用schema的测试数据
            if self.data_provider and api_name:
                schema_body_value = self.data_provider.get_param_value(api_name, f"{ref_name}_body")
                if schema_body_value is not None:
                    return schema_body_value
                    
            # 尝试从definitions中获取schema定义
            if hasattr(self, 'spec') and self.spec:
                definitions = self.spec.get('definitions', {})
                if ref_name in definitions:
                    schema_def = definitions[ref_name]
                    # 对于$ref引用，不使用ref_name作为前缀，直接传递None作为property_name
                    # 这样嵌套属性名就是直接的属性名，而不是ref_name.property_name
                    return self._generate_example_value(schema_def, None, api_name, depth + 1)
        
        # 检查schema中的类型
        schema_type = schema.get('type')
        
        if schema_type == 'integer':
            return 1
        elif schema_type == 'number':
            return 1.0
        elif schema_type == 'boolean':
            return True
        elif schema_type == 'string':
            # 检查字符串格式
            str_format = schema.get('format')
            if str_format == 'date':
                return datetime.now().strftime('%Y-%m-%d')
            elif str_format == 'date-time':
                return datetime.now().isoformat()
            elif str_format == 'email':
                return 'test@example.com'
            elif str_format == 'uuid':
                return '00000000-0000-0000-0000-000000000000'
            elif str_format == 'password':
                return 'Password123!'
            elif str_format == 'uri' or str_format == 'url':
                return 'https://example.com'
            
            # 检查是否有枚举值
            if 'enum' in schema and schema['enum']:
                return schema['enum'][0]
                
            # 根据属性名称生成示例
            if property_name:
                # 特定字段的特殊处理
                if property_name.lower() in ['email', 'mail']:
                    return 'test@example.com'
                elif property_name.lower() in ['password', 'pwd']:
                    return 'Password123!'
                elif property_name.lower() in ['phone', 'mobile', 'tel']:
                    return '13800138000'
                elif property_name.lower() in ['name', 'username']:
                    return 'test_user'
                elif property_name.lower() in ['id', 'userid']:
                    return 1
                else:
                    # 使用属性名作为示例值
                    return f"test_{property_name}"
            
            # 默认字符串值
            return "test_string"
            
        elif schema_type == 'array':
            items_schema = schema.get('items', {})
            # 生成一个只包含一个元素的数组
            return [self._generate_example_value(items_schema, property_name, api_name, depth + 1)]
            
        elif schema_type == 'object' or 'properties' in schema:
            result = {}
            # 处理所有属性
            properties = schema.get('properties', {})
            for prop_name, prop_schema in properties.items():
                # 构建嵌套属性名
                nested_prop_name = prop_name
                if property_name:
                    nested_prop_name = f"{property_name}.{prop_name}"
                    
                # 从Excel获取嵌套属性值
                if self.data_provider and api_name:
                    excel_value = self.data_provider.get_param_value(api_name, nested_prop_name)
                    if excel_value is not None and excel_value != '':
                        result[prop_name] = excel_value
                        continue
                    elif excel_value == '' or excel_value is None:
                        # 如果Excel中的值是空字符串或None，跳过这个属性
                        continue
                        
                generated_value = self._generate_example_value(prop_schema, nested_prop_name, api_name, depth + 1)
                if generated_value is not None:
                    result[prop_name] = generated_value
            return result
            
        # 对于引用类型，prance已经解析了引用
        # 如果没有type属性，尝试检查allOf, anyOf, oneOf
        if 'allOf' in schema:
            # 合并所有allOf的模式
            merged_schema = {}
            for sub_schema in schema['allOf']:
                if sub_schema.get('type') == 'object' or 'properties' in sub_schema:
                    properties = sub_schema.get('properties', {})
                    for prop_name, prop_schema in properties.items():
                        # 构建嵌套属性名
                        nested_prop_name = prop_name
                        if property_name:
                            nested_prop_name = f"{property_name}.{prop_name}"
                            
                        merged_schema[prop_name] = self._generate_example_value(prop_schema, nested_prop_name, api_name, depth + 1)
            return merged_schema
            
        if 'anyOf' in schema or 'oneOf' in schema:
            # 使用第一个选项
            options = schema.get('anyOf') or schema.get('oneOf')
            if options and len(options) > 0:
                return self._generate_example_value(options[0], property_name, api_name, depth + 1)
                
        # 默认返回空对象
        return {}
    
    def _parse_parameters(self, parameters: List[Dict], api_name: str = None) -> Tuple[Dict, Dict, Dict, Dict]:
        """解析操作的参数
        
        Args:
            parameters: 参数列表
            api_name: API名称，用于从Excel获取测试数据
            
        Returns:
            Tuple[Dict, Dict, Dict, Dict]: 查询参数、路径参数、表单数据、请求体数据
        """
        query_params = {}
        path_params = {}
        form_data = {}
        body_data = {}
        
        # 通用请求头参数，这些参数会在HttpClient中统一处理，不需要单独设置
        common_headers = ['AuthToken', 'DeviceId', 'DeviceType', 'Timestamp']
        
        for param in parameters:
            param_name = param.get('name')
            param_in = param.get('in')
            required = param.get('required', False)
            
            # 跳过通用请求头参数
            if param_name in common_headers:
                continue
                
            # 只处理必需的参数
            if required:
                schema = param.get('schema', {})
                if not schema and 'type' in param:
                    # Swagger 2.0风格的参数
                    schema = param
                    
                if param_in == 'query':
                    # 尝试从Excel获取测试数据
                    if self.data_provider and api_name:
                        excel_value = self.data_provider.get_param_value(api_name, param_name)
                        if excel_value is not None:
                            query_params[param_name] = excel_value
                            continue
                    # 否则生成默认值
                    query_params[param_name] = self._generate_example_value(schema, param_name, api_name, 0)
                elif param_in == 'path':
                    # 尝试从Excel获取测试数据
                    if self.data_provider and api_name:
                        excel_value = self.data_provider.get_param_value(api_name, param_name)
                        if excel_value is not None:
                            path_params[param_name] = excel_value
                            continue
                    # 否则生成默认值
                    path_params[param_name] = self._generate_example_value(schema, param_name, api_name, 0)
                elif param_in == 'formData':
                    if schema.get('type') != 'file':  # 文件类型单独处理
                        # 尝试从Excel获取测试数据
                        if self.data_provider and api_name:
                            excel_value = self.data_provider.get_param_value(api_name, param_name)
                            if excel_value is not None:
                                form_data[param_name] = excel_value
                                continue
                        # 否则生成默认值
                        form_data[param_name] = self._generate_example_value(schema, param_name, api_name, 0)
                elif param_in == 'body':
                    # 处理body参数
                    body_schema = param.get('schema', {})
                    
                    # 直接生成body数据，让_generate_example_value处理$ref引用
                    body_data = self._generate_example_value(body_schema, None, api_name, 0)
                        
        return query_params, path_params, form_data, body_data 
    
    def _parse_request_body(self, request_body: Dict, api_name: str = None) -> Dict:
        """解析请求体
        
        Args:
            request_body: 请求体定义
            api_name: API名称，用于从Excel获取测试数据
            
        Returns:
            Dict: 请求体示例数据
        """
        # 如果没有请求体，返回空对象
        if not request_body:
            return {}
            
        # OpenAPI 3.0风格的请求体
        if 'content' in request_body:
            # 尝试获取JSON格式的请求体
            json_content = request_body.get('content', {}).get('application/json', {})
            if json_content:
                schema = json_content.get('schema', {})
                
                # 从Excel获取测试数据并记录日志
                result = self._generate_example_value(schema, None, api_name, 0)
                if self.data_provider and api_name:
                    logger.info(f"API[{api_name}]的请求体数据: {result}")
                
                return result
                
            # 尝试获取表单格式的请求体
            form_content = (
                request_body.get('content', {}).get('application/x-www-form-urlencoded', {}) or
                request_body.get('content', {}).get('multipart/form-data', {})
            )
            if form_content:
                schema = form_content.get('schema', {})
                
                # 从Excel获取测试数据并记录日志
                result = self._generate_example_value(schema, None, api_name, 0)
                if self.data_provider and api_name:
                    logger.info(f"API[{api_name}]的表单数据: {result}")
                
                return result
                
        # Swagger 2.0风格的请求体参数已在_parse_parameters中处理
        return {}
    
    def _has_file_upload(self, parameters: List[Dict] = None, request_body: Dict = None) -> bool:
        """检查是否包含文件上传
        
        Args:
            parameters: 参数列表
            request_body: 请求体定义
            
        Returns:
            bool: 是否包含文件上传
        """
        # 检查参数中是否有文件上传
        if parameters:
            for param in parameters:
                if param.get('in') == 'formData' and param.get('type') == 'file':
                    return True
                    
        # 检查请求体中是否有文件上传
        if request_body and 'content' in request_body:
            if 'multipart/form-data' in request_body['content']:
                return True
                
        return False
    
    def _get_expected_status(self, responses: Dict) -> int:
        """获取预期的状态码
        
        Args:
            responses: 响应定义
            
        Returns:
            int: 预期状态码
        """
        # 查找2xx状态码
        for status in responses:
            if status.startswith('2'):
                return int(status)
                
        # 默认返回200
        return 200
    
    def _sanitize_operation_id(self, operation_id: str) -> str:
        """规范化operationId，使其适合作为Python方法名
        
        Args:
            operation_id: 原始operationId
            
        Returns:
            str: 规范化后的operationId
        """
        # 将驼峰命名转换为下划线命名
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', operation_id)
        s2 = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
        # 替换非法字符
        s3 = re.sub(r'[^a-zA-Z0-9_]', '_', s2)
        # 确保不以数字开头
        if s3[0].isdigit():
            s3 = 'op_' + s3
        return s3
    
    def _extract_response_schema(self, responses: Dict, operation_id: str) -> Dict:
        """提取响应的schema
        
        Args:
            responses: 响应定义
            operation_id: 操作ID
            
        Returns:
            Dict: 响应schema和期望的响应结构
        """
        result = {
            'expected_schema': None,
            'expected_response': None
        }
        
        # 查找2xx状态码
        for status, response in responses.items():
            if not status.startswith('2'):
                continue
                
            # 获取响应schema
            if 'schema' in response:
                # Swagger 2.0风格
                result['expected_schema'] = response['schema']
                
                # 生成期望的响应结构
                result['expected_response'] = self._generate_example_value(response['schema'], None, operation_id)
            elif 'content' in response:
                # OpenAPI 3.0风格
                json_content = response.get('content', {}).get('application/json', {})
                if json_content and 'schema' in json_content:
                    result['expected_schema'] = json_content['schema']
                    
                    # 生成期望的响应结构
                    result['expected_response'] = self._generate_example_value(json_content['schema'], None, operation_id)
                    
            break
            
        return result
    
    def generate_test_cases(self) -> bool:
        """生成测试用例
        
        Returns:
            bool: 是否成功生成测试用例
        """
        # if not self.spec:
        #     logger.error("未加载OpenAPI规范")
        #     return False
            
        try:
            # 创建输出目录
            os.makedirs(self.output_dir, exist_ok=True)
            
            # 按照标签分组API
            tag_operations = {}
            
            # 获取API信息
            info = self.spec.get('info', {})
            api_title = info.get('title', 'API')
            api_version = info.get('version', '1.0.0')
            
            # 获取所有路径
            paths = self.spec.get('paths', {})
            
            # 遍历所有路径
            for path, path_item in paths.items():
                # 遍历路径下的所有HTTP方法
                for method, operation in path_item.items():
                    if method not in ['get', 'post', 'put', 'delete', 'patch']:
                        continue
                        
                    # 获取操作信息
                    operation_id = operation.get('operationId')
                    if not operation_id:
                        # 如果没有operationId，根据路径和方法生成一个
                        path_part = path.replace('/', '_').replace('{', '').replace('}', '')
                        operation_id = f"{method}{path_part}"
                        
                    # 规范化operationId
                    operation_id = self._sanitize_operation_id(operation_id)
                    
                    # 获取操作摘要和描述
                    summary = operation.get('summary', operation_id)
                    description = operation.get('description', '')
                    
                    # 获取标签
                    tags = operation.get('tags', ['default'])
                    if not tags:
                        tags = ['default']
                        
                    # 获取参数
                    parameters = operation.get('parameters', [])
                    query_params, path_params, form_data, body_data = self._parse_parameters(parameters, operation.get('operationId'))
                    
                    # 替换路径中的参数
                    formatted_path = path
                    for param_name, param_value in path_params.items():
                        formatted_path = formatted_path.replace(f"{{{param_name}}}", str(param_value))
                    
                    # 获取请求体
                    request_body = None
                    request_body_data = {}
                    
                    # OpenAPI 3.0
                    if 'requestBody' in operation:
                        request_body = operation['requestBody']
                        request_body_data = self._parse_request_body(request_body, operation.get('operationId'))
                    
                    # 合并body_data和request_body_data
                    if body_data:
                        # 优先使用_parse_parameters中提取的body_data
                        logger.info(f"使用从parameters中提取的body_data: {body_data}")
                    elif request_body_data:
                        # 如果没有从parameters中提取到body_data，使用requestBody中的数据
                        body_data = request_body_data
                        logger.info(f"使用从requestBody中提取的body_data: {body_data}")
                    
                    # 检查是否有文件上传
                    has_file_upload = self._has_file_upload(parameters, request_body)
                    
                    # 获取响应
                    responses = operation.get('responses', {})
                    expected_status = self._get_expected_status(responses)
                    
                    # 提取响应schema
                    response_info = self._extract_response_schema(responses, operation.get('operationId'))
                    expected_schema = response_info['expected_schema']
                    expected_response = response_info['expected_response']
                    
                    # 创建测试用例
                    test_case = {
                        'operation_id': operation_id,
                        'original_operation_id': operation.get('operationId'),  # 保存原始操作ID
                        'summary': summary,
                        'description': description,
                        'path': formatted_path,
                        'method': method,
                        'query_params': query_params,
                        'body_data': body_data,
                        'form_data': form_data,
                        'has_file_upload': has_file_upload,
                        'expected_status': expected_status,
                        'expected_schema': expected_schema,
                        'expected_response': expected_response
                    }
                    
                    # 将测试用例添加到相应的标签中
                    for tag in tags:
                        if tag not in tag_operations:
                            tag_operations[tag] = []
                        tag_operations[tag].append(test_case)
            
            # 生成测试文件
            for tag, operations in tag_operations.items():
                if not operations:
                    continue
                    
                # 生成类名
                class_name = ''.join(word.capitalize() for word in tag.split('-'))
                
                # 生成文件名
                file_name = f"test_{tag.replace('-', '_')}.py"
                file_path = os.path.join(self.output_dir, file_name)
                
                # 生成测试类
                with open(file_path, 'w', encoding='utf-8') as f:
                    # 写入文件头部
                    f.write(f"#!/usr/bin/env python\n")
                    f.write(f"# -*- coding: utf-8 -*-\n\n")
                    f.write(f"# 自动生成的测试用例\n")
                    f.write(f"# API: {api_title}\n")
                    f.write(f"# 版本: {api_version}\n")
                    f.write(f"# 标签: {tag}\n")
                    f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    # 写入导入语句
                    f.write("import pytest\n")
                    f.write("import json\n")
                    f.write("import time\n")
                    f.write("import os\n")
                    f.write("import tempfile\n")
                    f.write("from utils.http_client import HttpClient\n")
                    f.write("from config.config import Config\n\n\n")
                    
                    # 写入测试类
                    f.write(f"@pytest.mark.{tag.replace('-', '_')}\n")
                    f.write(f"class Test{class_name}:\n")
                    f.write(f'    """测试 {tag} 相关接口"""\n\n')
                    
                    # 写入setup_class方法
                    f.write("    @classmethod\n")
                    f.write("    def setup_class(cls):\n")
                    f.write('        """测试类初始化"""\n')
                    f.write("        cls.client = HttpClient()  # 使用HttpClient处理请求和认证\n")
                    f.write("        \n")
                    f.write("        # 先登录获取token\n")
                    f.write('        login_url = "/api/user/login"\n')
                    f.write("        login_data = Config.TEST_USER\n")
                    f.write("        login_response = cls.client.post(login_url, json=login_data)\n")
                    f.write("        \n")
                    f.write("        if login_response.status_code == 200:\n")
                    f.write("            try:\n")
                    f.write("                login_data = login_response.json()\n")
                    f.write('                print(f"登录响应: {login_data}")\n')
                    f.write("                # 检查登录是否成功并获取token\n")
                    f.write("                if login_data.get('code') == 200 and login_data.get('data') is not None and 'token' in login_data['data']:\n")
                    f.write("                    token = login_data['data']['token']\n")
                    f.write('                    print(f"成功获取token: {token}")\n')
                    f.write("                    # HttpClient会自动处理认证头\n")
                    f.write("                else:\n")
                    f.write("                    error_message = login_data.get('message', '未知错误')\n")
                    f.write("                    error_code = login_data.get('code', '未知状态码')\n")
                    f.write('                    print(f"登录失败，状态码: {error_code}, 错误: {error_message}")\n')
                    f.write('                    print(f"响应内容: {login_response.text}")\n')
                    f.write('                    pytest.skip(f"登录失败: {error_message} (代码: {error_code})")\n')
                    f.write("            except Exception as e:\n")
                    f.write('                print(f"解析响应时出错: {str(e)}")\n')
                    f.write('                print(f"响应内容: {login_response.text}")\n')
                    f.write('                pytest.skip(f"登录时发生错误: {str(e)}")\n')
                    f.write("        else:\n")
                    f.write('            print(f"登录失败，状态码: {login_response.status_code}")\n')
                    f.write('            print(f"响应内容: {login_response.text}")\n')
                    f.write('            pytest.skip(f"登录失败，状态码: {login_response.status_code}")\n')
                    f.write("    \n")
                    
                    # 写入teardown_class方法
                    f.write("    @classmethod\n")
                    f.write("    def teardown_class(cls):\n")
                    f.write('        """测试类清理"""\n')
                    f.write("        # HttpClient会自动处理会话的关闭\n")
                    f.write("        \n")
                    
                    # 写入setup_method方法
                    f.write("    def setup_method(self):\n")
                    f.write('        """每个测试方法前执行"""\n')
                    f.write("        # 确保每个测试之间有足够的时间间隔，避免API限流\n")
                    f.write("        time.sleep(0.5)\n\n")
                    
                    # 写入测试方法
                    for op in operations:
                        method_name = op['operation_id']
                        summary = op['summary']
                        description = op['description']
                        path = op['path']
                        http_method = op['method']
                        query_params = op['query_params']
                        body_data = op['body_data']
                        form_data = op.get('form_data', {})
                        has_file_upload = op['has_file_upload']
                        expected_status = op['expected_status']
                        expected_schema = op['expected_schema']
                        expected_response = op['expected_response']
                        
                        # 检查是否需要跳过此API
                        skip_test = False
                        skip_reason = ""
                        if self.data_provider:
                            skip_test = self.data_provider.is_api_skipped(op.get('original_operation_id', method_name))
                            if skip_test:
                                skip_reason = "在Excel中标记为跳过"
                        
                        # 写入测试方法
                        f.write(f"    def test_{method_name}(self):\n")
                        f.write(f'        """测试 {summary}\n')
                        if description:
                            f.write(f"\n{description}\n")
                        f.write('"""\n')
                        
                        # 如果需要跳过，添加跳过标记
                        if skip_test:
                            f.write(f'        pytest.skip("{skip_reason}")\n\n')
                        
                        f.write(f'        url = "{path}"\n')
                        f.write("        \n")
                        f.write(f"        params = {json.dumps(query_params, ensure_ascii=False)}\n")
                        
                        # 处理不同类型的请求
                        if has_file_upload:
                            # 文件上传请求
                            f.write("        \n")
                            f.write("        # 创建临时文件用于测试\n")
                            f.write("        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as temp:\n")
                            f.write("            temp.write(b'This is a test file content')\n")
                            f.write("            temp_path = temp.name\n")
                            f.write("        \n")
                            f.write("        try:\n")
                            f.write("            # 准备文件上传\n")
                            f.write("            files = {'file': ('test_file.txt', open(temp_path, 'rb'), 'text/plain')}\n")
                            f.write("            \n")
                            f.write("            # 如果有其他表单数据\n")
                            f.write(f"            data = {json.dumps(form_data, ensure_ascii=False)}\n")
                            f.write("            \n")
                            f.write(f"            response = self.client.{http_method}(url, params=params, data=data, files=files)\n")
                            f.write("        finally:\n")
                            f.write("            # 清理临时文件\n")
                            f.write("            if os.path.exists(temp_path):\n")
                            f.write("                os.unlink(temp_path)\n")
                        elif http_method in ['post', 'put', 'patch'] and body_data:
                            # JSON请求体
                            f.write("        \n")
                            f.write(f"        json_data = {json.dumps(body_data, ensure_ascii=False)}\n")
                            f.write(f"        response = self.client.{http_method}(url, params=params, json=json_data)\n")
                        elif form_data:
                            # 表单数据请求
                            f.write("        \n")
                            f.write(f"        form_data = {json.dumps(form_data, ensure_ascii=False)}\n")
                            f.write(f"        response = self.client.{http_method}(url, params=params, data=form_data)\n")
                        else:
                            # 简单请求
                            f.write("        \n")
                            f.write(f"        response = self.client.{http_method}(url, params=params)\n")
                        
                        # 断言和验证
                        f.write("        \n")
                        f.write(f"        # 断言\n")
                        f.write(f"        assert response.status_code == {expected_status}, f\"期望状态码 {expected_status}, 实际状态码 {{response.status_code}}\"\n")
                        f.write("        \n")
                        f.write("        # 打印响应内容，便于调试\n")
                        f.write("        print(f\"响应状态码: {response.status_code}\")\n")
                        f.write("        print(f\"响应内容: {response.text}\")\n")
                        f.write("        \n")
                        f.write("        # 验证响应格式\n")
                        f.write("        try:\n")
                        f.write("            response_data = response.json()\n")
                        f.write("            assert isinstance(response_data, dict), \"响应应该是JSON格式\"\n")
                        f.write("            \n")
                        f.write("            # 验证业务状态码\n")
                        f.write("            if 'code' in response_data:\n")
                        f.write("                assert response_data['code'] in [200, 0], f\"业务状态码错误: {response_data['code']}\"\n")
                        f.write("            \n")
                        f.write("            # 验证响应中是否包含数据\n")
                        f.write("            if 'data' in response_data:\n")
                        f.write("                assert response_data['data'] is not None, \"响应数据不应为空\"\n")
                        
                        # 添加响应schema验证（如果有期望的响应结构）
                        if expected_response:
                            f.write("                \n")
                            f.write("                # 验证响应数据结构\n")
                            f.write("                expected_response = ")
                            # 将期望的响应结构格式化为Python代码字符串
                            expected_response_str = json.dumps(expected_response, ensure_ascii=False)
                            f.write(f"{expected_response_str}\n")
                            f.write("                \n")
                            f.write("                # 验证响应中的关键字段\n")
                            f.write("                if isinstance(expected_response, dict) and isinstance(response_data.get('data'), dict):\n")
                            f.write("                    for key in expected_response.keys():\n")
                            f.write("                        if key in response_data.get('data', {}):\n")
                            f.write("                            print(f\"响应包含期望的字段: {key}\")\n")
                            f.write("                \n")
                        
                        f.write("        except ValueError:\n")
                        f.write("            # 某些接口可能不返回JSON，例如文件下载\n")
                        f.write("            if 'application/json' in response.headers.get('Content-Type', ''):\n")
                        f.write("                pytest.fail(\"响应声明为JSON但解析失败\")\n")
                        f.write("        \n")
                        
                logger.info(f"已生成测试文件: {file_path}")
            
            return True
        except Exception as e:
            logger.error(f"生成测试用例时出错: {str(e)}")
            return False


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='使用prance解析OpenAPI/Swagger文档并生成测试用例')
    parser.add_argument('openapi_file', help='OpenAPI/Swagger文件路径')
    parser.add_argument('--output', '-o', default='api_test_new/testcases/generated', help='输出目录')
    parser.add_argument('--strict', '-s', action='store_true', help='是否进行严格验证')
    parser.add_argument('--recursion-limit', '-r', type=int, default=100, help='引用解析的递归限制，默认100')
    parser.add_argument('--no-resolve', '-n', action='store_true', help='不解析引用，直接使用原始规范')
    parser.add_argument('--excel-data', '-e', help='Excel测试数据文件路径')
    
    args = parser.parse_args()
    
    # 创建生成器
    generator = OpenAPITestGenerator(
        args.openapi_file, 
        args.output, 
        args.strict, 
        args.recursion_limit,
        not args.no_resolve,  # 如果指定了--no-resolve，则不解析引用
        args.excel_data  # Excel测试数据文件路径
    )
    
    # 加载OpenAPI规范
    if not generator.load_spec():
        logger.error("加载OpenAPI规范失败")
        return
        
    # 生成测试用例
    if generator.generate_test_cases():
        logger.info("测试用例生成成功")
    else:
        logger.error("测试用例生成失败")


if __name__ == '__main__':
    main() 