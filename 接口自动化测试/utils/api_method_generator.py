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


SWAGGER_PATH = os.path.join("test_data", "swagger", "swagger_fixed.json")



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


def _build_method_block(method_name: str, http_method: str, path: str, summary: str) -> str:
    """构建符合用户模板的方法代码块（缩进与现有文件一致，4空格）"""
    summary_text = summary or path
    today = datetime.now().strftime("%Y-%m-%d")
    # GET 使用 params，其他使用 json；允许 **kwargs 透传
    request_line = (
        f"response = requests.request(\"{http_method}\", url, headers=headers, params=kwargs)"
        if http_method.upper() == "GET"
        else f"response = requests.request(\"{http_method}\", url, headers=headers, json=kwargs)"
    )
    return (
        f"\n    def {method_name}(self, authorization, DeviceType=\"web\", **kwargs):\n"
        f"        \"\"\"\n"
        f"        {summary_text}\n"
        f"        :param page:\n"
        f"        :return:\n"
        f"        \"\"\"\n"
        f"        # Create Data:  自动生成 {today}\n"
        f"        # Creator: Swagger Generator\n"
        f"        # Update Date:\n"
        f"        # updater:\n"
        f"        # Update Details:\n"
        f"        url = f\"https://{{base_url}}{path}\"\n"
        f"        timestamp = str(int(time.time() * 1000))\n"
        f"        headers = self.request_header(timestamp, authorization, DeviceType)\n"
        f"        {request_line}\n"
        f"        error_msg = \"{summary_text}\"\n"
        f"        assert response.status_code == 200, f\"{{error_msg}}失败，url->{{url}}，失败信息->{{response.reason}}{{response.content}}\"\n"
        f"        response = response.json()\n"
        f"        assert \"data\" in response,  f\"{{error_msg}}返回结果没有data数据，url->{{url}}，response->{{response}}\"\n"
        f"        return response[\"data\"]\n"
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
    # 读取 swagger
    if not os.path.exists(SWAGGER_PATH):
        raise FileNotFoundError(f"未找到 Swagger 文件: {SWAGGER_PATH}")
    with open(SWAGGER_PATH, "r", encoding="utf-8") as f:
        swagger = json.load(f)

    items = _extract_course_paths(
        swagger,
        include_exact=include_exact,
        include_prefix=include_prefix,
        include_regex=include_regex,
        only_course_related=only_course_related,
        methods=methods,
    )
    if not items:
        print("未找到匹配的接口路径。")
        return

    # 读取并定位 CourseApi 类，准备在文件末尾追加（维持缩进）
    api_file = os.getcwd() + os.path.join("/test_case", "page_api", module, f"{module}_api.py")
    if not os.path.exists(api_file):
        raise FileNotFoundError(f"未找到 API 文件: {api_file}")
    with open(api_file, "r", encoding="utf-8") as f:
        content = f.read()

    # 仅检查 CourseApi 类以保持与现有结构兼容
    if f"class {module.capitalize()}Api(" not in content:
        raise RuntimeError(f"未在目标文件中找到 {module.capitalize()}Api 类定义")

    # 生成方法块（若方法名已存在则跳过）
    blocks_to_add: List[str] = []
    skipped = 0
    for http_method, path, summary in items:
        method_name = _camelize_from_path(path, http_method)
        # 在目标文件中检测是否已有同名方法
        signature_token = f"\n    def {method_name}("
        if signature_token in content:
            skipped += 1
            continue
        blocks_to_add.append(_build_method_block(method_name, http_method, path, summary))

    if not blocks_to_add:
        print(f"无新增方法可写入（跳过 {skipped} 个已存在的方法）。目标文件: {api_file}")
        return

    new_content = content.rstrip() + "\n" + "\n".join(blocks_to_add) + "\n"

    with open(api_file, "w", encoding="utf-8") as f:
        f.write(new_content)

    print(f"已新增 {len(blocks_to_add)} 个方法写入: {api_file}（跳过 {skipped} 个已存在的方法）")


if __name__ == "__main__":
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


