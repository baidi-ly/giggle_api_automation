#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API接口扫描工具
用于扫描接口测试文档，对比page_api下的API方法，找出缺失的接口
"""

import os
import re
import json
import ast
from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass


@dataclass
class ApiInfo:
    """API接口信息"""
    url: str
    method: str
    description: str = ""
    controller: str = ""
    module: str = ""


class ApiScanner:
    """API接口扫描器"""
    
    def __init__(self, doc_path: str = "test_data/接口测试文档_v1.19.0.md", 
                 page_api_path: str = "test_case/page_api"):
        self.doc_path = doc_path
        self.page_api_path = page_api_path
        self.api_difference_file = "test_data/api_difference.json"
        
    def scan_api_document(self) -> List[ApiInfo]:
        """
        扫描接口测试文档，提取所有接口信息
        
        Returns:
            List[ApiInfo]: 接口信息列表
        """
        if not os.path.exists(self.doc_path):
            print(f"接口文档不存在: {self.doc_path}")
            return []
            
        with open(self.doc_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        apis = []
        
        # 使用正则表达式匹配接口信息
        # 匹配模式：**接口地址**: `METHOD /path`
        pattern = r'\*\*接口地址\*\*:\s*`(GET|POST|PUT|DELETE|PATCH)\s+([^`]+)`'
        
        matches = re.findall(pattern, content)
        
        for method, url in matches:
            # 清理URL，去掉可能的参数
            clean_url = url.strip()
            
            # 保持URL原样，不自动添加/api前缀
            # 这样接口文档中的 /donate/createDonateOrder 就保持为 /donate/createDonateOrder
            # 而 /admin/activity/list 就保持为 /admin/activity/list
            
            # 提取描述信息（在接口地址后面的几行内）
            description = self._extract_description(content, method, url.strip())  # 使用原始URL提取描述
            
            # 提取控制器信息
            controller = self._extract_controller(content, method, url.strip())  # 使用原始URL提取控制器
            
            # 推断模块名
            module = self._infer_module_from_url(clean_url)
            
            api_info = ApiInfo(
                url=clean_url,
                method=method.upper(),
                description=description,
                controller=controller,
                module=module
            )
            apis.append(api_info)
        
        print(f"从文档中扫描到 {len(apis)} 个接口")
        return apis
    
    def _extract_description(self, content: str, method: str, url: str) -> str:
        """提取接口描述"""
        # 查找接口地址后面的描述
        pattern = rf'\*\*接口地址\*\*:\s*`{method}\s+{re.escape(url)}`\s*\n\*\*接口描述\*\*:\s*([^\n]+)'
        match = re.search(pattern, content)
        if match:
            return match.group(1).strip()
        return ""
    
    def _extract_controller(self, content: str, method: str, url: str) -> str:
        """提取控制器信息"""
        # 查找控制器信息
        pattern = rf'\*\*接口地址\*\*:\s*`{method}\s+{re.escape(url)}`[\s\S]*?\*\*控制器\*\*:\s*([^\n]+)'
        match = re.search(pattern, content)
        if match:
            return match.group(1).strip()
        return ""
    
    def _infer_module_from_url(self, url: str) -> str:
        """从URL推断模块名"""
        # 去掉开头的斜杠
        url = url.lstrip('/')
        
        # 分割URL路径
        parts = url.split('/')
        
        # 跳过 'api' 前缀
        if parts and parts[0] == 'api':
            parts = parts[1:]
        
        if not parts:
            return "unknown"
        
        # 取第一个路径段作为模块名
        module = parts[0]
        
        # 特殊处理：admin开头的接口
        if module.startswith('admin'):
            return f"admin_{module.replace('admin', '').lstrip('_')}"
        
        return module
    
    def scan_page_api_methods(self) -> Dict[str, Set[str]]:
        """
        扫描page_api目录下的所有API方法
        
        Returns:
            Dict[str, Set[str]]: 模块名 -> 方法名集合的映射
        """
        api_methods = {}
        
        if not os.path.exists(self.page_api_path):
            print(f"page_api目录不存在: {self.page_api_path}")
            return api_methods
        
        # 遍历page_api目录
        for root, dirs, files in os.walk(self.page_api_path):
            # 跳过__pycache__目录
            if '__pycache__' in root:
                continue
                
            for file in files:
                if file.endswith('_api.py'):
                    file_path = os.path.join(root, file)
                    module_name = self._extract_module_name_from_path(file_path)
                    methods = self._extract_methods_from_file(file_path)
                    
                    if methods:
                        api_methods[module_name] = methods
        
        print(f"从page_api中扫描到 {len(api_methods)} 个模块的API方法")
        return api_methods
    
    def _extract_module_name_from_path(self, file_path: str) -> str:
        """从文件路径提取模块名"""
        # 获取相对于page_api的路径
        rel_path = os.path.relpath(file_path, self.page_api_path)
        
        # 去掉文件名，只保留目录路径
        dir_path = os.path.dirname(rel_path)
        
        # 如果文件在子目录中，使用子目录名
        if dir_path and dir_path != '.':
            return dir_path
        else:
            # 如果文件在根目录，从文件名提取
            filename = os.path.basename(file_path)
            return filename.replace('_api.py', '')
    
    def _extract_methods_from_file(self, file_path: str) -> Set[str]:
        """从Python文件中提取API方法名"""
        methods = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 使用AST解析Python代码
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # 跳过私有方法（以_开头）
                    if not node.name.startswith('_'):
                        methods.add(node.name)
        
        except Exception as e:
            print(f"解析文件 {file_path} 时出错: {e}")
        
        return methods
    
    def _extract_url_from_api_file(self, file_path: str) -> Set[str]:
        """
        从API文件中提取所有的URL路径
        
        Args:
            file_path: API文件路径
            
        Returns:
            Set[str]: 提取到的URL路径集合
        """
        urls = set()
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # 使用正则表达式匹配URL
            # 匹配形如: url = f"https://{base_url}/api/xxx" 或 url = f"https://{base_url}/admin/xxx"
            url_pattern = r'url\s*=\s*f?"https://\{base_url\}/([^"]+)"'
            matches = re.findall(url_pattern, content)
            
            for match in matches:
                # 去掉可能的参数占位符，只保留路径结构
                clean_url = match.strip()
                urls.add(clean_url)
                
        except Exception as e:
            print(f"读取API文件失败 {file_path}: {e}")
            
        return urls
    
    def _find_matching_url(self, api_info: ApiInfo, page_api_dir: str) -> bool:
        """
        查找是否有匹配的URL路径
        
        Args:
            api_info: API信息
            page_api_dir: page_api目录路径
            
        Returns:
            bool: 是否找到匹配的URL
        """
        # 1. 确定要查找的目标URL
        target_url = api_info.url.strip('/')
        
        # 2. 根据URL类型确定搜索范围
        if target_url.startswith('admin/'):
            # admin开头的URL，在page_api/admin下查找，不需要添加/api前缀
            search_dir = os.path.join(page_api_dir, 'admin')
            expected_url = target_url  # 直接使用原URL
        else:
            # 其他URL，在page_api下所有文件中查找，需要添加/api前缀
            search_dir = page_api_dir
            expected_url = f"api/{target_url}"  # 添加api前缀
        
        # 3. 扫描指定目录下的所有Python文件
        if not os.path.exists(search_dir):
            return False
            
        for root, dirs, files in os.walk(search_dir):
            for file in files:
                if file.endswith('.py') and file != '__init__.py':
                    file_path = os.path.join(root, file)
                    urls = self._extract_url_from_api_file(file_path)
                    
                    # 4. 检查是否有匹配的URL
                    for url in urls:
                        if self._is_url_match(url, expected_url):
                            return True
                            
        return False
    
    def _is_url_match(self, actual_url: str, expected_url: str) -> bool:
        """
        判断两个URL是否匹配
        
        Args:
            actual_url: 实际URL（从API文件中提取）
            expected_url: 期望URL（从接口文档中提取）
            
        Returns:
            bool: 是否匹配
        """
        # 去掉首尾的斜杠
        actual_url = actual_url.strip('/')
        expected_url = expected_url.strip('/')
        
        # 直接比较
        if actual_url == expected_url:
            return True
            
        # 处理参数占位符的匹配
        # 将{param}替换为通配符进行匹配
        actual_pattern = re.sub(r'\{[^}]+\}', '[^/]+', actual_url)
        expected_pattern = re.sub(r'\{[^}]+\}', '[^/]+', expected_url)
        
        # 使用正则表达式匹配
        actual_regex = re.compile(f'^{actual_pattern}$')
        expected_regex = re.compile(f'^{expected_pattern}$')
        
        return actual_regex.match(expected_url) is not None or expected_regex.match(actual_url) is not None

    def _find_matching_method(self, expected_method: str, module_methods: Set[str], api_info: ApiInfo) -> Optional[str]:
        """
        查找匹配的方法名，支持多种命名风格
        
        Args:
            expected_method: 期望的方法名
            module_methods: 模块中实际存在的方法名集合
            api_info: API信息
            
        Returns:
            Optional[str]: 找到的匹配方法名，如果没有找到则返回None
        """
        # 1. 精确匹配
        if expected_method in module_methods:
            return expected_method
        
        # 2. 从URL路径提取可能的候选方法名
        url_parts = api_info.url.strip('/').split('/')
        # 去掉api前缀
        if url_parts and url_parts[0] == 'api':
            url_parts = url_parts[1:]
        
        # 3. 生成多种可能的方法名
        candidates = set()
        
        # 3.1 使用URL的最后一部分（去掉参数）
        if url_parts:
            last_part = url_parts[-1]
            # 去掉参数占位符
            last_part = re.sub(r'\{[^}]+\}', '', last_part)
            if last_part:
                candidates.add(last_part)
        
        # 3.2 去掉HTTP方法前缀的方法名
        # 例如：getHealth -> health, postUser -> user
        if expected_method.startswith(('get', 'post', 'put', 'delete', 'patch')):
            # 去掉方法前缀
            without_prefix = expected_method[3:] if expected_method.startswith(('get', 'put')) else expected_method[4:]
            if without_prefix:
                candidates.add(without_prefix)
        
        # 3.3 去掉_details后缀
        if expected_method.endswith('_details'):
            without_details = expected_method[:-8]
            candidates.add(without_details)
        
        # 3.4 对于GET请求，尝试去掉get前缀
        if api_info.method.upper() == 'GET' and expected_method.startswith('get'):
            without_get = expected_method[3:]
            if without_get:
                candidates.add(without_get)
        
        # 3.5 根据HTTP方法生成可能的Auto方法名
        # 例如：PUT /api/school/class/{classId} -> putAuto
        #      DELETE /api/school/class/{classId} -> deleteAuto
        http_method = api_info.method.upper()
        if http_method in ['PUT', 'DELETE']:
            auto_method = f"{http_method.lower()}Auto"
            candidates.add(auto_method)
            
            # 也尝试带数字的版本（如putAuto1, deleteAuto1）
            auto_method_num = f"{http_method.lower()}Auto1"
            candidates.add(auto_method_num)
        
        # 3.6 尝试匹配包含HTTP方法的方法名，并根据URL路径智能选择
        # 例如：putAuto, deleteAuto, putAuto1, deleteAuto1
        for method_name in module_methods:
            if method_name.startswith(http_method.lower()) and 'Auto' in method_name:
                candidates.add(method_name)
        
        # 3.7 根据URL路径资源类型智能匹配
        # 如果URL包含student，优先匹配带数字的版本（如putAuto1, deleteAuto1）
        # 如果URL包含class，优先匹配不带数字的版本（如putAuto, deleteAuto）
        if 'student' in api_info.url.lower():
            # 对于student资源，优先匹配带数字的Auto方法
            for method_name in module_methods:
                if method_name.startswith(http_method.lower()) and 'Auto1' in method_name:
                    candidates.add(method_name)
        elif 'class' in api_info.url.lower():
            # 对于class资源，优先匹配不带数字的Auto方法
            for method_name in module_methods:
                if method_name.startswith(http_method.lower()) and 'Auto' in method_name and 'Auto1' not in method_name:
                    candidates.add(method_name)
        
        # 4. 根据优先级检查候选方法名
        # 4.1 首先检查精确匹配
        if expected_method in module_methods:
            return expected_method
        
        # 4.2 根据URL路径和HTTP方法组合进行智能匹配
        http_method = api_info.method.upper()
        url_lower = api_info.url.lower()
        
        # 优先级匹配规则
        priority_matches = []
        
        if 'student' in url_lower:
            # 对于student资源，优先匹配带数字的Auto方法
            if http_method == 'PUT':
                priority_matches.extend(['putAuto1', 'putAuto'])
            elif http_method == 'DELETE':
                priority_matches.extend(['deleteAuto1', 'deleteAuto'])
        elif 'class' in url_lower:
            # 对于class资源，优先匹配不带数字的Auto方法
            if http_method == 'PUT':
                priority_matches.extend(['putAuto', 'putAuto1'])
            elif http_method == 'DELETE':
                priority_matches.extend(['deleteAuto', 'deleteAuto1'])
        
        # 检查优先级匹配
        for priority_method in priority_matches:
            if priority_method in module_methods:
                return priority_method
        
        # 4.3 检查其他候选方法名
        for candidate in candidates:
            if candidate in module_methods:
                return candidate
        
        return None
    
    def generate_expected_method_name(self, api_info: ApiInfo) -> str:
        """根据API信息生成期望的方法名"""
        try:
            from utils.api_method_generator import _camelize_from_path
            return _camelize_from_path(api_info.url, api_info.method)
        except ImportError:
            # 如果无法导入，使用简单的命名规则
            url_parts = api_info.url.strip('/').split('/')
            if url_parts and url_parts[0] == 'api':
                url_parts = url_parts[1:]
            
            if url_parts:
                last_part = url_parts[-1]
                # 去掉参数占位符
                last_part = re.sub(r'\{[^}]+\}', '', last_part)
                if last_part:
                    return f"{api_info.method.lower()}{last_part.capitalize()}"
            
            return f"{api_info.method.lower()}Api"
    
    def compare_apis(self, doc_apis: List[ApiInfo], page_api_dir: str) -> List[Dict]:
        """
        对比文档中的接口和page_api中的URL，找出缺失的接口
        
        Args:
            doc_apis: 文档中的接口列表
            page_api_dir: page_api目录路径
            
        Returns:
            List[Dict]: 缺失的接口信息列表
        """
        missing_apis = []
        
        for api_info in doc_apis:
            # 使用URL匹配检查接口是否已被覆盖
            is_covered = self._find_matching_url(api_info, page_api_dir)
            
            if not is_covered:
                # 生成期望的方法名（用于显示）
                expected_method = self.generate_expected_method_name(api_info)
                
                missing_apis.append({
                    'url': api_info.url,
                    'method': api_info.method,
                    'expected_method_name': expected_method,
                    'module': api_info.module,
                    'description': api_info.description,
                    'controller': api_info.controller,
                    'reason': f'URL {api_info.url} 在page_api中未找到匹配的封装方法'
                })
        
        print(f"发现 {len(missing_apis)} 个缺失的接口")
        return missing_apis
    
    def _deduplicate_apis(self, missing_apis: List[Dict]) -> List[Dict]:
        """
        对缺失的接口进行去重处理
        
        Args:
            missing_apis: 原始缺失接口列表
            
        Returns:
            List[Dict]: 去重后的接口列表
        """
        seen = set()
        deduplicated = []
        
        for api in missing_apis:
            # 只使用URL作为唯一标识符，忽略HTTP方法
            url = api['url']
            
            if url not in seen:
                seen.add(url)
                deduplicated.append(api)
            else:
                print(f"发现重复接口: {api['method']} {api['url']}")
        
        return deduplicated
    
    def save_missing_apis(self, missing_apis: List[Dict]) -> None:
        """将缺失的接口保存到JSON文件"""
        # 确保目录存在
        os.makedirs(os.path.dirname(self.api_difference_file), exist_ok=True)
        
        # 去重处理：基于URL进行去重（忽略HTTP方法）
        deduplicated_apis = self._deduplicate_apis(missing_apis)
        
        # 只保存URL信息（不包含HTTP方法）
        urls_only = [api["url"] for api in deduplicated_apis]
        
        # 转换为generate_cases.py期望的格式
        output_data = {
            'apis': urls_only,
            'scan_time': str(datetime.now()),
            'total_count': len(deduplicated_apis),
            'original_count': len(missing_apis),
            'duplicates_removed': len(missing_apis) - len(deduplicated_apis)
        }
        
        # 保存到JSON文件
        with open(self.api_difference_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        
        print(f"缺失的接口已保存到: {self.api_difference_file}")
        if output_data['duplicates_removed'] > 0:
            print(f"已去除 {output_data['duplicates_removed']} 个重复接口")
    
    def run_scan(self) -> List[Dict]:
        """
        执行完整的扫描流程
        
        Returns:
            List[Dict]: 缺失的接口信息列表
        """
        print("开始扫描接口文档...")
        doc_apis = self.scan_api_document()
        
        print("开始对比接口...")
        page_api_dir = "test_case/page_api"
        missing_apis = self.compare_apis(doc_apis, page_api_dir)
        
        print("保存缺失的接口...")
        self.save_missing_apis(missing_apis)
        
        return missing_apis


def main():
    """主函数"""
    scanner = ApiScanner()
    missing_apis = scanner.run_scan()
    
    if missing_apis:
        print(f"\n发现 {len(missing_apis)} 个缺失的接口:")
        for i, api in enumerate(missing_apis, 1):
            print(f"{i}. {api['method']} {api['url']} -> {api['expected_method_name']} ({api['module']})")
            print(f"   原因: {api['reason']}")
            print()
    else:
        print("\n所有接口都已实现！")


if __name__ == "__main__":
    main()
