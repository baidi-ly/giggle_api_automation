#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
从 test_data/swagger_fixed.json 读取包含 course 的接口，
按指定模板在 test_case/page_api/course/course_api.py 的 CourseApi 类中追加方法。

方法模板示例（返回 response["data"] 且校验 data 存在）：
    def sample(self, authorization, DeviceType="web"):
        """
        摘要
        :param page:
        :return:
        """
        # Create Data:  自动生成
        # Creator: Swagger Generator
        # Update Date:
        # updater:
        # Update Details:
        url = f"https://{base_url}/api/..."
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "摘要"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        assert "data" in response,  f"{error_msg}返回结果没有data数据，url->{url}，response->{response}"
        return response["data"]
'''

import json
import os
import re
import keyword
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional, Iterable
import argparse
from config import RunConfig
VersionId = RunConfig.VersionId


SWAGGER_PATH = os.getcwd() + os.path.join(r"/test_data", "swagger", "swagger_fixed.json")



def _camelize_from_path(path: str, http_method: str) -> str:
    """基于路径和 HTTP 方法生成方法名，如 GET /api/user/kids -> getKids"""
    # 去掉前缀与参数占位
    parts = [re.sub(r"\{[^}]+\}", "", p) for p in path.strip("/").split("/") if p and p not in ("api",)]
    if not parts:
        return "autoMethod"
    # 末段优先，否则合并
    tail = parts[-1] if parts[-1] else "auto"
    tail_camel = re.sub(r"[^A-Za-z0-9]", "", "".join([w.capitalize() for w in tail.split("-") if w]))
    verb = {
        "GET": "get",
        "POST": "post",
        "PUT": "put",
        "DELETE": "delete",
        "PATCH": "patch",
    }.get(http_method.upper(), "do")
    # 特例：当末段是 detail 或 listAllWithLevel 等已是驼峰词，直接拼接
    if not tail_camel:
        tail_camel = "Auto"
    # 规则调整：POST 不加动词前缀，其它方法保持原规则
    if http_method.upper() == "POST":
        # lowerCamel，如 bindApple
        if tail_camel:
            name = tail_camel[0].lower() + tail_camel[1:]
        else:
            name = "auto"
    else:
        # 避免方法名与已有方法冲突：不强制加 get 前缀时，尽量遵循现有风格
        if tail_camel and tail_camel[0].isupper():
            name = verb + tail_camel
        else:
            name = verb + (tail_camel[0].upper() + tail_camel[1:] if tail_camel else "Auto")
    
    # 检查是否与Python关键字冲突
    if keyword.iskeyword(name):
        # 如果方法名与Python关键字冲突，使用倒数第二个单词作为前缀
        if len(parts) >= 2:
            prefix = parts[-2]  # 倒数第二个单词
            prefix_camel = re.sub(r"[^A-Za-z0-9]", "", "".join([w.capitalize() for w in prefix.split("-") if w]))
            if prefix_camel:
                name = prefix_camel[0].lower() + prefix_camel[1:] + "_" + name
            else:
                name = prefix + "_" + name
        else:
            # 如果没有倒数第二个单词，添加默认前缀
            name = "api_" + name
    
    return name


def _build_method_block(
    method_name: str,
    http_method: str,
    path: str,
    summary: str,
    is_update: bool = False,
    body_params: Optional[List[Dict[str, Any]]] = None,
    path_params: Optional[List[Dict[str, Any]]] = None,
    query_params: Optional[List[Dict[str, Any]]] = None,
    form_params: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """构建符合用户模板的方法代码块（缩进与现有文件一致，4空格）"""
    summary_text = summary or path
    today = datetime.now().strftime("%Y-%m-%d")
    
    # 构建方法参数
    method_params = ["self", "authorization"]

    # 先添加 path 参数到方法签名（确保可用于 f-string URL）
    if path_params:
        for param in path_params:
            pname = param.get("name", "")
            ptype = (param.get("type") or "string").lower()
            prequired = bool(param.get("required", False))
            pdefault = param.get("default")
            if ptype == "integer":
                default_value = str(pdefault) if isinstance(pdefault, int) else "0"
            elif ptype == "boolean":
                default_value = (str(pdefault).lower() if isinstance(pdefault, bool) else "False")
            else:
                default_value = f"'{pdefault}'" if isinstance(pdefault, str) and pdefault is not None else "''"
            method_params.append(f"{pname}={default_value}")
    
    # 检查body参数是否有示例数据
    has_body_examples = False
    if body_params:
        for param in body_params:
            if 'schema' in param and 'example' in param['schema']:
                has_body_examples = True
                break
    
    # 只有当body参数没有示例数据时，才添加到方法签名中
    if body_params and not has_body_examples:
        for param in body_params:
            param_name = param.get("name", "")
            param_type = param.get("type", "string")
            param_required = param.get("required", False)
            param_default = param.get("default", "")
            
            # 根据参数类型和是否必填设置默认值
            if param_required:
                if param_type == "string":
                    default_value = f"'{param_default}'" if param_default else "''"
                elif param_type == "integer":
                    default_value = param_default if param_default else "0"
                elif param_type == "boolean":
                    default_value = str(param_default).lower() if param_default is not None else "False"
                elif param_type == "object":
                    # 对于object类型，使用JSON字符串
                    import json
                    default_value = json.dumps(param_default, ensure_ascii=False) if param_default else "{}"
                else:
                    default_value = "''"
            else:
                if param_type == "string":
                    default_value = f"'{param_default}'" if param_default else "''"
                elif param_type == "integer":
                    default_value = param_default if param_default else "0"
                elif param_type == "boolean":
                    default_value = str(param_default).lower() if param_default is not None else "False"
                elif param_type == "object":
                    # 对于object类型，使用JSON字符串
                    import json
                    default_value = json.dumps(param_default, ensure_ascii=False) if param_default else "{}"
                else:
                    default_value = "''"
            
            method_params.append(f"{param_name}={default_value}")

    # 添加 query 参数到方法签名
    if query_params:
        for param in query_params:
            param_name = param.get("name", "")
            param_type = param.get("type", "string")
            param_default = param.get("default", "")
            if param_type == "integer":
                default_value = param_default if isinstance(param_default, int) else "0"
            elif param_type == "boolean":
                default_value = str(param_default).lower() if isinstance(param_default, bool) else "False"
            else:
                default_value = f"'{param_default}'" if isinstance(param_default, str) and param_default else "''"
            method_params.append(f"{param_name}={default_value}")

    # formData 文件上传：按照需求仅暴露 file 参数
    has_form = bool(form_params)
    has_file_param = False
    if has_form:
        method_params.append("file=None")
        # 检查是否有file类型的参数
        for param in form_params:
            if param.get("type") == "file":
                has_file_param = True
                break
    
    # 添加其他标准参数
    method_params.extend(["DeviceType=\"web\"", "code=200", "**kwargs"])
    method_signature = ", ".join(method_params)
    
    # 构建 payload 代码
    payload_code = ""
    payload_lines: List[str] = []
    has_query = bool(query_params)
    has_body = bool(body_params)
    # 同时存在 query 与 body 时，沿用 payload1/payload2；否则统一使用 payload
    if has_query and has_body:
        q_items = []
        for param in query_params:
            pname = param.get("name", "")
            q_items.append(f'            "{pname}": {pname}')
        q_joined = ",\n".join(q_items)
        payload_lines.append("        payload1 = {\n" + q_joined + "\n        }")
        b_items = []
        for param in body_params:
            pname = param.get("name", "")
            b_items.append(f'            "{pname}": {pname}')
        b_joined = ",\n".join(b_items)
        payload_lines.append("        payload2 = {\n" + b_joined + "\n        }")
        payload_lines.append("        payload2 = self.request_body(payload2, **kwargs)")
    elif has_query:
        q_items = []
        for param in query_params:
            pname = param.get("name", "")
            q_items.append(f'            "{pname}": {pname}')
        q_joined = ",\n".join(q_items)
        payload_lines.append("        payload = {\n" + q_joined + "\n        }")
    elif has_body:
        # 检查是否有JSON示例数据，将所有body参数的示例数据组合成完整的JSON
        json_example = {}
        has_examples = False
        
        for param in body_params:
            if 'schema' in param and 'example' in param['schema']:
                json_example[param['name']] = param['schema']['example']
                has_examples = True
        
        if has_examples:
            # 手动构建格式化的JSON字符串
            payload_lines.append("        payload = {")
            for i, (key, value) in enumerate(json_example.items()):
                if isinstance(value, dict):
                    # 处理嵌套对象
                    payload_lines.append(f'            "{key}": {{')
                    for j, (nested_key, nested_value) in enumerate(value.items()):
                        comma = "," if j < len(value) - 1 else ""
                        if isinstance(nested_value, str):
                            payload_lines.append(f'                "{nested_key}": "{nested_value}"{comma}')
                        else:
                            payload_lines.append(f'                "{nested_key}": {nested_value}{comma}')
                    comma = "," if i < len(json_example) - 1 else ""
                    payload_lines.append(f'            }}{comma}')
                else:
                    # 处理简单值
                    comma = "," if i < len(json_example) - 1 else ""
                    if isinstance(value, str):
                        payload_lines.append(f'            "{key}": "{value}"{comma}')
                    else:
                        payload_lines.append(f'            "{key}": {value}{comma}')
            payload_lines.append("        }")
            payload_lines.append("        payload = self.request_body(payload, **kwargs)")
        else:
            # 使用参数构建payload
            b_items = []
            for param in body_params:
                pname = param.get("name", "")
                b_items.append(f'            "{pname}": {pname}')
            b_joined = ",\n".join(b_items)
            payload_lines.append("        payload = {\n" + b_joined + "\n        }")
            payload_lines.append("        payload = self.request_body(payload, **kwargs)")
    if payload_lines:
        payload_code = "\n".join(payload_lines) + "\n"
    
    # 构建请求行
    # 组合请求：按是否存在 query/body/formData 动态传参
    method_upper = http_method.upper()
    args_parts: List[str] = ["\"" + method_upper + "\"", "url", "headers=headers"]
    if has_query and has_body:
        args_parts.append("params=payload1")
        if method_upper in ("POST", "PUT", "PATCH", "DELETE"):
            args_parts.append("json=payload2")
    elif has_query:
        # 如果有文件上传，query参数应该作为data传递（multipart/form-data）
        if has_form and method_upper in ("POST", "PUT", "PATCH", "DELETE"):
            args_parts.append("data=payload")
        else:
            args_parts.append("params=payload")
    elif has_body and method_upper in ("POST", "PUT", "PATCH", "DELETE"):
        args_parts.append("json=payload")
    if has_body and method_upper == "GET":
        # GET 一般不带 body，这里忽略 body
        pass
    if has_form:
        args_parts.append("files=file")
    request_line = f"response = requests.request(" + ", ".join(args_parts) + ")"
    
    # 根据是否为更新模式生成不同的注释
    if is_update:
        comment_block = (
            f"        # Create Data:  {VersionId}  &  {today}\n"
            f"        # Update Date:  {VersionId}  &  {today}\n"
            f"        # Update Details:  接口更新\n"
        )
    else:
        comment_block = (
            f"        # Create Data:  {VersionId}  &  {today}\n"
        )
    
    # 将路径中的占位符 {id} 保持为单括号，以便生成的 f-string 在运行时替换
    import re as _re_internal
    path_code = _re_internal.sub(r"\{([^}]+)\}", r"{\1}", path)

    # 生成 docstring 参数说明（排除 authorization / DeviceType / code / kwargs）
    def _param_type(p: Dict[str, Any]) -> str:
        t = p.get("type")
        if not t and isinstance(p.get("schema"), dict):
            t = p["schema"].get("type", "object")
        return (t or "string")

    param_doc_lines: List[str] = []
    if path_params:
        for p in path_params:
            name = p.get("name", "")
            if not name:
                continue
            typ = _param_type(p)
            req = "required" if p.get("required") else "optional"
            desc = p.get("description") or name
            param_doc_lines.append(f"        :param {name}: ({typ}, path, {req}) {desc}")
    if body_params:
        for p in body_params:
            name = p.get("name", "")
            if not name:
                continue
            typ = _param_type(p)
            req = "required" if p.get("required") else "optional"
            desc = p.get("description") or name
            param_doc_lines.append(f"        :param {name}: ({typ}, body, {req}) {desc}")
    if query_params:
        for p in query_params:
            name = p.get("name", "")
            if not name:
                continue
            typ = _param_type(p)
            req = "required" if p.get("required") else "optional"
            desc = p.get("description") or name
            param_doc_lines.append(f"        :param {name}: ({typ}, query, {req}) {desc}")
    if has_form:
        param_doc_lines.append("        :param file: (file, formData, optional) 上传文件")
    params_doc = "\n".join(param_doc_lines)
    
    # 构建headers生成代码
    if has_file_param:
        # 当接口包含file类型参数时，设置Content-Type为multipart/form-data
        headers_code = "        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')"
    else:
        headers_code = "        headers = self.request_header(timestamp, authorization, DeviceType)"

    return (
        f"\n    def {method_name}({method_signature}):\n"
        f"        \"\"\"\n"
        f"        {summary_text}\n"
        f"{params_doc}\n"
        f"        :return: 接口原始返回（已 json 解析）\n"
        f"        \"\"\"\n"
        f"{comment_block}"
        f"        url = f\"https://{{base_url}}{path_code}\"\n"
        f"{payload_code}"
        f"        timestamp = str(int(time.time() * 1000))\n"
        f"{headers_code}\n"
        f"\n"
        f"        {request_line}\n"
        f"        error_msg = \"{summary_text}\"\n"
        f"        assert response.status_code == code, f\"{{error_msg}}失败，url->{{url}}，失败信息->{{response.reason}}{{response.content}}\"\n"
        f"        try:\n"
        f"            response = response.json()\n"
        f"            return response\n"
        f"        except json.decoder.JSONDecodeError:\n"
        f"            return False\n"
    )


def _extract_course_paths(
    swagger: Dict[str, Any],
    include_exact: Optional[Iterable[str]] = None,
    include_prefix: Optional[Iterable[str]] = None,
    include_regex: Optional[str] = None,
    only_course_related: bool = True,
    methods: Optional[Iterable[str]] = None,
) -> List[Tuple[str, str, str]]:
    """
    返回 (http_method, path, summary) 列表。

    - include_exact: 仅包含与这些完整路径完全匹配的项（可多次）。
    - include_prefix: 仅包含以任一前缀开头的路径（可多次）。
    - include_regex: 使用正则匹配路径。
    - only_course_related: 为 True 时，仅筛选包含 /course 的路径。
    - methods: 仅包含指定 HTTP 方法集合（如 ["GET","POST"]）。
    """
    results: List[Tuple[str, str, str]] = []
    paths = swagger.get("paths", {})
    regex_obj = re.compile(include_regex) if include_regex else None
    method_set = {m.upper() for m in methods} if methods else {"GET", "POST", "PUT", "DELETE", "PATCH"}

    for path, meta in paths.items():
        low = path.lower()

        if only_course_related and "/course" not in low:
            continue

        if include_exact is not None:
            if path not in set(include_exact):
                continue

        if include_prefix is not None:
            if not any(path.startswith(p) for p in include_prefix):
                continue

        if regex_obj is not None and not regex_obj.search(path):
            continue

        for http_method, detail in meta.items():
            if http_method.upper() not in method_set:
                continue
            summary = detail.get("summary", "") or ""
            results.append((http_method.upper(), path, summary))
    return results


def generate_methods_to_api(
    module: str = "course",
    include_exact: Optional[List[str]] = None,
    include_prefix: Optional[List[str]] = None,
    include_regex: Optional[str] = None,
    only_course_related: bool = True,
    methods: Optional[List[str]] = None,
):
    """批量生成接口方法（已弃用，请使用 generate_single_method_to_api）"""
    print("警告：批量生成模式已弃用，请使用 --single 模式生成单个接口方法")
    print("示例：python api_method_generator.py --single --path /api/course/content/detail --http-method GET")
    return


def _compare_interfaces(
    existing_method: str,
    new_path: str,
    new_http_method: str,
    new_parameters: Optional[List[Dict[str, Any]]] = None
) -> bool:
    """
    比较两个接口是否相同
    
    Args:
        existing_method: 已存在方法的完整代码
        new_path: 新接口路径
        new_http_method: 新接口HTTP方法
        new_parameters: 新接口参数
    
    Returns:
        bool: True表示接口相同，False表示接口不同
    """
    # 提取已存在方法的URL和HTTP方法
    import re
    
    # 提取URL - 修复正则表达式
    url_match = re.search(r'url = f"https://\{base_url\}([^"]+)"', existing_method)
    existing_path = url_match.group(1) if url_match else ""
    
    # 提取HTTP方法
    method_match = re.search(r'requests\.request\("([^"]+)"', existing_method)
    existing_http_method = method_match.group(1) if method_match else ""
    
    print(f"调试: 已存在方法内容前100字符: {existing_method[:100]}")
    print(f"调试: 已存在接口路径: '{existing_path}', HTTP方法: '{existing_http_method}'")
    print(f"调试: 新接口路径: '{new_path}', HTTP方法: '{new_http_method}'")
    
    # 比较路径和HTTP方法
    if existing_path != new_path or existing_http_method.upper() != new_http_method.upper():
        print(f"调试: 接口不同 - 路径或HTTP方法不匹配")
        return False
    
    # 如果提供了新参数，比较参数
    if new_parameters is not None:
        # 提取已存在方法的参数 - 只提取当前方法内的参数
        # 查找方法定义开始到下一个方法定义之间的参数
        method_start = existing_method.find('def ')
        if method_start != -1:
            # 找到方法定义后的第一个三引号
            docstring_start = existing_method.find('"""', method_start)
            if docstring_start != -1:
                # 找到文档字符串结束
                docstring_end = existing_method.find('"""', docstring_start + 3)
                if docstring_end != -1:
                    # 只在这个范围内提取参数
                    docstring_content = existing_method[docstring_start:docstring_end + 3]
                    param_matches = re.findall(r':param (\w+):', docstring_content)
                    existing_param_names = set(param_matches)
                else:
                    existing_param_names = set()
            else:
                existing_param_names = set()
        else:
            existing_param_names = set()
        
        # 提取新参数的名称
        new_param_names = set()
        for param in new_parameters:
            if param.get("in") in ["body", "path", "query", "formData"]:
                new_param_names.add(param.get("name", ""))
        
        print(f"调试: 已存在参数: {existing_param_names}")
        print(f"调试: 新参数: {new_param_names}")
        
        # 比较参数名称集合
        if existing_param_names != new_param_names:
            print(f"调试: 接口不同 - 参数不匹配")
            return False
    
    print(f"调试: 接口相同")
    return True


def _find_next_method_name(content: str, base_method_name: str) -> str:
    """
    找到下一个可用的方法名
    
    Args:
        content: 文件内容
        base_method_name: 基础方法名
    
    Returns:
        str: 下一个可用的方法名
    """
    import re
    
    # 查找所有已存在的方法名
    existing_methods = re.findall(rf'\n    def ({base_method_name}\d*)\s*\(', content)
    
    if base_method_name not in existing_methods:
        return base_method_name
    
    # 找到最大的数字后缀
    max_num = 0
    for method in existing_methods:
        if method == base_method_name:
            continue
        # 提取数字后缀
        match = re.match(rf'{base_method_name}(\d+)', method)
        if match:
            num = int(match.group(1))
            max_num = max(max_num, num)
    
    return f"{base_method_name}{max_num + 1}"


def generate_single_method_to_api(
    path: str,
    http_method: str,
    module: str = "course",
    summary: Optional[str] = None,
    force: bool = False,
    parameters: Optional[List[Dict[str, Any]]] = None,
):
    """
    生成单个接口方法到指定的 API 文件中
    
    Args:
        path: 接口路径，如 "/api/course/content/detail"
        http_method: HTTP 方法，如 "GET", "POST" 等
        module: 目标模块目录名，如 "course", "book" 等
        summary: 接口摘要，如果不提供则从 swagger 中获取
        force: 是否强制覆盖已存在的方法
    """
    # 初始化参数列表
    body_params: List[Dict[str, Any]] = []
    path_params: List[Dict[str, Any]] = []
    query_params: List[Dict[str, Any]] = []
    form_params: List[Dict[str, Any]] = []
    
    # 如果提供了参数，使用提供的参数；否则从 swagger 中读取
    if parameters is not None:
        # 使用提供的参数
        for param in parameters:
            if param.get("in") == "body":
                body_params.append(param)
            elif param.get("in") == "path":
                path_params.append(param)
            elif param.get("in") == "query":
                query_params.append(param)
            elif param.get("in") == "formData":
                form_params.append(param)
    else:
        # 从 swagger 中读取参数（保持向后兼容）
        if not os.path.exists(SWAGGER_PATH):
            raise FileNotFoundError(f"未找到 Swagger 文件: {SWAGGER_PATH}")
        
        with open(SWAGGER_PATH, "r", encoding="utf-8") as f:
            swagger = json.load(f)
        
        paths = swagger.get("paths", {})
        
        if path in paths and (http_method.lower() in paths[path] or http_method.upper() in paths[path]):
            interface_info = paths[path].get(http_method.lower()) or paths[path].get(http_method.upper())
            if not summary:
                summary = interface_info.get("summary", "")
            
            # 提取 parameters 中 in 类型为 body/path/query/formData 的参数
            swagger_parameters = interface_info.get("parameters", [])
            for param in swagger_parameters:
                if param.get("in") == "body":
                    body_params.append(param)
                elif param.get("in") == "path":
                    path_params.append(param)
                elif param.get("in") == "query":
                    query_params.append(param)
                elif param.get("in") == "formData":
                    form_params.append(param)
        else:
            if not summary:
                summary = path
    
    # 读取并定位 API 类文件
    # 判断是否为admin接口
    if module.startswith("admin_"):
        # admin接口写入到test_case/page_api/admin目录
        api_file = os.path.join("test_case", "page_api", "admin", f"{module}.py")
    else:
        # 普通接口写入到test_case/page_api目录
        api_file = os.path.join("test_case", "page_api", module, f"{module}_api.py")
    if not os.path.exists(api_file):
        if module.startswith("admin_"):
            # admin接口文件不存在，创建admin目录和文件
            admin_dir = os.path.join("test_case", "page_api", "admin")
            os.makedirs(admin_dir, exist_ok=True)
            # 创建基本的API类文件
            class_name = f"Admin{module.replace('admin_', '').replace('_api', '').capitalize()}Api"
            basic_content = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
{module} API接口
"""

import requests
import time
from config import RunConfig

base_url = RunConfig.base_url


class {class_name}:
    """API接口类"""
    
    def __init__(self):
        self.base_url = base_url
    
    def request_header(self, timestamp, authorization, DeviceType="web"):
        """构建请求头"""
        return {{
            "Authorization": authorization,
            "DeviceType": DeviceType,
            "timestamp": timestamp,
            "Content-Type": "application/json"
        }}
'''
            with open(api_file, "w", encoding="utf-8") as f:
                f.write(basic_content)
        else:
            # 如果标准文件名不存在，尝试查找目录下的其他 .py 文件
            module_dir = os.path.join("test_case", "page_api", module)
            if os.path.exists(module_dir):
                py_files = [f for f in os.listdir(module_dir) if f.endswith('.py') and f != '__init__.py']
                if py_files:
                    api_file = os.path.join(module_dir, py_files[0])
                else:
                    raise FileNotFoundError(f"未找到 API 文件: {api_file}")
            else:
                raise FileNotFoundError(f"未找到 API 文件: {api_file}")
    
    with open(api_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    # 检查目标类是否存在
    if module.startswith("admin_"):
        class_name = f"Admin{module.replace('admin_', '').replace('_api', '').capitalize()}Api"
    else:
        class_name = f"{module.capitalize()}Api"
    
    if f"class {class_name}(" not in content:
        raise RuntimeError(f"未在目标文件中找到 {class_name} 类定义")
    
    # 生成方法名
    method_name = _camelize_from_path(path, http_method)
    
    # 检查方法是否已存在
    signature_token = f"\n    def {method_name}("
    method_exists = signature_token in content

    # 若方法已存在：检查接口是否相同
    if method_exists:
        # 找到所有匹配的方法位置
        import re
        method_positions = []
        # 转义正则表达式特殊字符
        escaped_token = re.escape(signature_token)
        for match in re.finditer(escaped_token, content):
            method_positions.append(match.start())
        
        print(f"调试: 找到 {len(method_positions)} 个匹配的方法: {method_name}")
        
        # 检查每个已存在的方法是否与新接口相同
        for start_pos in method_positions:
            # 切片出该方法的完整文本块
            tail = content[start_pos:]
            lines = tail.split('\n')
            method_lines = []
            indent_level = None
            end_index = None
            print(f"调试: 找到方法 {method_name}，开始提取...")
            for i, line in enumerate(lines):
                if i == 0:
                    method_lines.append(line)
                    print(f"调试: 第0行: '{line}'")
                    continue
                if indent_level is None and line.strip():
                    indent_level = len(line) - len(line.lstrip())
                    print(f"调试: 设置缩进级别为 {indent_level}")
                if line.strip() and indent_level is not None:
                    current_indent = len(line) - len(line.lstrip())
                    print(f"调试: 第{i}行缩进: {current_indent}, 内容: '{line[:50]}...'")
                    # 修复逻辑：如果当前行缩进小于方法缩进，且不是空行，则说明是下一个方法或类
                    if current_indent < indent_level and line.strip():
                        end_index = i
                        print(f"调试: 找到方法结束位置 {end_index}")
                        break
                method_lines.append(line)
            if end_index is None:
                end_index = len(lines)
                print(f"调试: 方法到文件末尾，共 {end_index} 行")

            existing_method = '\n'.join(method_lines)
            print(f"调试: 提取到的方法长度: {len(existing_method)}")
            
            # 比较接口是否相同
            if _compare_interfaces(existing_method, path, http_method, parameters):
                print(f"方法 {method_name} 已存在且接口相同，跳过生成")
                return f"SKIP:{method_name}"  # 返回特殊标识，表示跳过生成
        
        # 如果所有已存在的方法都与新接口不同，需要生成新的方法名
        method_name = _find_next_method_name(content, method_name)
        print(f"方法名冲突，接口不同，使用新方法名: {method_name}")
        # 重新检查新方法名是否存在
        signature_token = f"\n    def {method_name}("
        method_exists = signature_token in content

    # 若方法已存在（可能是新生成的方法名）：在原注释中追加 Update 行（不破坏原有 Create Data 等注释）
    if method_exists:
        # 重新提取方法内容（因为方法名可能已经改变）
        start_pos = content.find(signature_token)
        if start_pos == -1:
            print(f"未能定位已存在的方法: {method_name}")
            return

        # 切片出该方法的完整文本块
        tail = content[start_pos:]
        lines = tail.split('\n')
        method_lines = []
        indent_level = None
        end_index = None
        for i, line in enumerate(lines):
            if i == 0:
                method_lines.append(line)
                continue
            if indent_level is None and line.strip():
                indent_level = len(line) - len(line.lstrip())
            if line.strip() and indent_level is not None:
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= indent_level and not line.startswith(' ' * (indent_level + 1)):
                    end_index = i
                    break
            method_lines.append(line)
        if end_index is None:
            end_index = len(lines)

        old_method = '\n'.join(method_lines)

        # 在 old_method 中查找 Create Data 注释，并在其后插入 Update 注释（若未存在）
        create_marker = "# Create Data:"
        update_date_marker = "# Update Date:"
        update_details_marker = "# Update Details:"
        if update_date_marker in old_method or update_details_marker in old_method:
            print(f"方法 {method_name} 已包含更新注释，跳过追加")
            return method_name

        insert_idx = old_method.find(create_marker)
        if insert_idx == -1:
            # 未找到 Create Data，则不做破坏性修改，直接返回
            print(f"方法 {method_name} 未找到 Create Data 注释，跳过追加")
            return method_name

        # 计算插入位置到该行末尾
        line_start = old_method.rfind('\n', 0, insert_idx) + 1
        line_end = old_method.find('\n', insert_idx)
        if line_end == -1:
            line_end = len(old_method)
        existing_line = old_method[line_start:line_end]

        # 保持与现有注释相同的缩进
        leading_spaces = ''
        for ch in existing_line:
            if ch == ' ':
                leading_spaces += ' '
            else:
                break

        from datetime import datetime
        today = datetime.now().strftime("%Y-%m-%d")
        update_block = (
            f"\n{leading_spaces}# Update Date:  {VersionId}  &  {today}\n"
            f"{leading_spaces}# Update Details:  接口更新"
        )

        new_method = old_method[:line_end] + update_block + old_method[line_end:]
        new_content = content.replace(old_method, new_method, 1)

        with open(api_file, "w", encoding="utf-8") as f:
            f.write(new_content)
        print(f"已在方法 {method_name} 的注释下追加 Update 信息: {api_file}")
        return method_name

    # 方法不存在：走新增逻辑，生成带 Create Data 注释的方法块
    method_block = _build_method_block(
        method_name,
        http_method,
        path,
        summary,
        is_update=False,
        body_params=body_params,
        path_params=path_params,
        query_params=query_params,
        form_params=form_params,
    )
    new_content = content.rstrip() + "\n" + method_block + "\n"
    with open(api_file, "w", encoding="utf-8") as f:
        f.write(new_content)
    print(f"已新增方法 {method_name} 到文件: {api_file}")
    if body_params:
        param_names = [param.get("name", "") for param in body_params]
        print(f"  - 包含 body 参数: {', '.join(param_names)}")
    
    return method_name



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Swagger -> CourseApi 方法生成器")
    parser.add_argument("--module", default="course", help="目标模块目录名（如 course、book 等），默认 course")
    
    # 单个接口生成参数
    parser.add_argument("--single", action="store_true", help="生成单个接口方法")
    parser.add_argument("--path", help="单个接口的路径，如 '/api/course/content/detail'")
    parser.add_argument("--http-method", help="HTTP 方法，如 'GET', 'POST' 等")
    parser.add_argument("--summary", help="接口摘要，如果不提供则从 swagger 中获取")
    parser.add_argument("--force", action="store_true", help="强制覆盖已存在的方法")
    
    # 批量生成参数
    parser.add_argument("--include-path", dest="include_exact", action="append", help="仅生成这些精确路径的接口，可多次")
    parser.add_argument("--include-prefix", dest="include_prefix", action="append", help="仅生成以此前缀开头的接口，可多次")
    parser.add_argument("--include-regex", dest="include_regex", help="使用正则筛选路径")
    parser.add_argument("--all-paths", dest="all_paths", action="store_true", help="包含所有路径（不只限 /course）")
    parser.add_argument("--method", dest="methods", action="append", help="仅生成指定 HTTP 方法，如 --method GET，可多次")

    args = parser.parse_args()
    
    # 根据参数选择生成方式
    if args.single:
        if not args.path or not args.http_method:
            print("错误：使用 --single 模式时必须提供 --path 和 --http-method 参数")
            exit(1)
        generate_single_method_to_api(
            path=args.path,
            http_method=args.http_method,
            module=args.module,
            summary=args.summary,
            force=args.force,
        )
    else:
        # 默认批量生成模式
        generate_methods_to_api(
            module=args.module,
            include_exact=args.include_exact,
            include_prefix=args.include_prefix,
            include_regex=args.include_regex,
            only_course_related=(not args.all_paths),
            methods=args.methods,
        )


