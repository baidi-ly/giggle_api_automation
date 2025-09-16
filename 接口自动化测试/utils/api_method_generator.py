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
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional, Iterable
import argparse
from config import RunConfig
VersionId = RunConfig.VersionId


SWAGGER_PATH = os.getcwd() + os.path.join(r"\test_data", "swagger", "swagger_fixed.json")



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
    # 避免方法名与已有方法冲突：不强制加 get 前缀时，尽量遵循现有风格
    if tail_camel[0].isupper():
        name = verb + tail_camel
    else:
        name = verb + tail_camel[0].upper() + tail_camel[1:]
    return name


def _build_method_block(
    method_name: str,
    http_method: str,
    path: str,
    summary: str,
    is_update: bool = False,
    body_params: Optional[List[Dict[str, Any]]] = None,
    path_params: Optional[List[Dict[str, Any]]] = None,
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
    
    # 添加 body 参数到方法签名
    if body_params:
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
                    default_value = param_default.lower() if param_default else "False"
                else:
                    default_value = "''"
            else:
                if param_type == "string":
                    default_value = f"'{param_default}'" if param_default else "''"
                elif param_type == "integer":
                    default_value = param_default if param_default else "0"
                elif param_type == "boolean":
                    default_value = param_default.lower() if param_default else "False"
                else:
                    default_value = "''"
            
            method_params.append(f"{param_name}={default_value}")
    
    # 添加其他标准参数
    method_params.extend(["DeviceType=\"web\"", "code=200", "**kwargs"])
    method_signature = ", ".join(method_params)
    
    # 构建 payload 代码
    payload_code = ""
    if body_params:
        payload_items = []
        for param in body_params:
            param_name = param.get("name", "")
            payload_items.append(f'            "{param_name}": {param_name}')
        payload_code = f"        payload = {{\n{chr(10).join(payload_items)}\n        }}\n        payload = self.request_body(payload, **kwargs)\n"
    
    # 构建请求行
    if body_params:
        # 有 body 参数时使用 json=payload
        request_line = f"response = requests.request(\"{http_method}\", url, headers=headers, json=payload)"
    else:
        # 没有 body 参数时使用原来的逻辑
        request_line = (
            f"response = requests.request(\"{http_method}\", url, headers=headers, params=kwargs)"
            if http_method.upper() == "GET"
            else f"response = requests.request(\"{http_method}\", url, headers=headers, json=kwargs)"
        )
    
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

    return (
        f"\n    def {method_name}({method_signature}):\n"
        f"        \"\"\"\n"
        f"        {summary_text}\n"
        f"        :param:\n"
        f"        :return:\n"
        f"        \"\"\"\n"
        f"{comment_block}"
        f"        url = f\"https://{{base_url}}{path_code}\"\n"
        f"        timestamp = str(int(time.time() * 1000))\n"
        f"{payload_code}"
        f"        headers = self.request_header(timestamp, authorization, DeviceType)\n"
        f"\n"
        f"        {request_line}\n"
        f"        error_msg = \"{summary_text}\"\n"
        f"        assert response.status_code == code, f\"{{error_msg}}失败，url->{{url}}，失败信息->{{response.reason}}{{response.content}}\"\n"
        f"        response = response.json()\n"
        f"        return response\n"
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


def generate_single_method_to_api(
    path: str,
    http_method: str,
    module: str = "course",
    summary: Optional[str] = None,
    force: bool = False,
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
    # 读取 swagger 获取接口信息
    if not os.path.exists(SWAGGER_PATH):
        raise FileNotFoundError(f"未找到 Swagger 文件: {SWAGGER_PATH}")
    
    with open(SWAGGER_PATH, "r", encoding="utf-8") as f:
        swagger = json.load(f)
    
    # 从 swagger 中获取接口摘要和 body/path 参数
    paths = swagger.get("paths", {})
    body_params: List[Dict[str, Any]] = []
    path_params: List[Dict[str, Any]] = []
    
    if path in paths and (http_method.lower() in paths[path] or http_method.upper() in paths[path]):
        interface_info = paths[path].get(http_method.lower()) or paths[path].get(http_method.upper())
        if not summary:
            summary = interface_info.get("summary", "")
        
        # 提取 parameters 中 in 类型为 body 与 path 的参数
        parameters = interface_info.get("parameters", [])
        for param in parameters:
            if param.get("in") == "body":
                body_params.append(param)
            elif param.get("in") == "path":
                path_params.append(param)
    else:
        if not summary:
            summary = path
    
    # 读取并定位 API 类文件
    api_file = os.path.join("test_case", "page_api", module, f"{module}_api.py")
    if not os.path.exists(api_file):
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
    if f"class {module.capitalize()}Api(" not in content:
        raise RuntimeError(f"未在目标文件中找到 {module.capitalize()}Api 类定义")
    
    # 生成方法名
    method_name = _camelize_from_path(path, http_method)
    
    # 检查方法是否已存在
    signature_token = f"\n    def {method_name}("
    method_exists = signature_token in content

    # 若方法已存在：在原注释中追加 Update 行（不破坏原有 Create Data 等注释）
    if method_exists:
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


