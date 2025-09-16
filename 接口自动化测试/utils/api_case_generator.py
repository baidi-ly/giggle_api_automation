#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
单接口用例生成工具（供代码中直接调用）：
- 无业务参数（除 authorization/DeviceType）→ 生成 1 条直接调用
- 有必填参数 → 生成【缺失必填】与【填写必填】两条
- 有可选参数 → 追加 1 条包含可选参数

公开方法：
- generate_single_api_tests(module, class_name, method_name, required_params, optional_params, marker, doc)
- generate_tests_by_spec(path, api_method, required, optional, marker, doc)
"""

import os
import re
from typing import Dict, Any, List, Tuple
import argparse


HEADER_TMPL = """import pytest
import sys
import os

sys.path.append(os.getcwd())

from test_case.page_api.{module}.{module}_api import {class_name}


@pytest.mark.{marker}
class Test{class_name}Generated:
    def setup_class(self):
        self.api = {class_name}()
        self.authorization = self.api.get_authorization()
"""


def _infer_module_and_class_from_path(path: str) -> Tuple[str, str]:
    """从 /api/<module>/... 或 /admin/<module>/... 推断 (module, class_name)"""
    m = re.match(r"^/(api|admin)/([^/]+)", path or "")
    module = (m.group(2) if m else "course").strip()
    module = module.split("-")[0]
    class_name = module.capitalize() + "Api"
    return module, class_name


def _ensure_test_file(file_path: str, module: str, class_name: str, marker: str) -> None:
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(HEADER_TMPL.format(module=module, class_name=class_name, marker=marker))


def _case_name(prefix: str, method_name: str, suffix: str) -> str:
    return f"test_{prefix}_{method_name}_{suffix}"


def _render_kwargs(kwargs: Dict[str, Any]) -> str:
    parts: List[str] = []
    for k, v in kwargs.items():
        if isinstance(v, str) and not v.startswith("self."):
            parts.append(f"{k}='{v}'")
        else:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def _append_case(file_path: str, name: str, doc: str, call_expr: str, assert_data: bool = True) -> None:
    lines = [
        "\n",
        "\n",
        f"    def {name}(self):\n",
        f"        \"\"\"{doc}\"\"\"\n",
        f"        res = {call_expr}\n",
        f"        assert isinstance(res, dict), f'接口返回类型异常: {{type(res)}}'\n",
    ]
    if assert_data:
        lines.append("        assert 'data' in res, f'返回结果没有data数据，response->{res}'\n")
    with open(file_path, "a", encoding="utf-8") as f:
        f.writelines(lines)


def generate_single_api_tests(
    *,
    module: str,
    class_name: str,
    method_name: str,
    required_params: List[str] = None,
    optional_params: List[str] = None,
    marker: str = "Auto",
    doc: str = "",
) -> str:
    """生成并追加用例，返回目标测试文件路径"""
    required_params = required_params or []
    optional_params = optional_params or []

    test_dir = os.path.join("test_case", f"test_{module}_case")
    test_file = os.path.join(test_dir, f"test_{module}_api.py")
    _ensure_test_file(test_file, module, class_name, marker)

    # 情况1：无业务参数
    if not required_params and not optional_params:
        kwargs = {"authorization": "self.authorization"}
        call = f"self.api.{method_name}({_render_kwargs(kwargs)})"
        _append_case(test_file, _case_name("noargs", method_name, "basic"), doc or method_name, call)
        return test_file

    # 情况2：有必填参数 → 缺失/填写
    if required_params:
        # 缺失必填：仅带鉴权
        kwargs_miss = {"authorization": "self.authorization"}
        call_miss = f"self.api.{method_name}({_render_kwargs(kwargs_miss)})"
        _append_case(test_file, _case_name("required_missing", method_name, "error_or_assert"), f"{doc or method_name}-缺失必填参数", call_miss, assert_data=False)

        # 填写必填：占位值（数字1）
        kwargs_fill: Dict[str, Any] = {p: 1 for p in required_params}
        kwargs_fill["authorization"] = "self.authorization"
        call_fill = f"self.api.{method_name}({_render_kwargs(kwargs_fill)})"
        _append_case(test_file, _case_name("required_filled", method_name, "ok"), f"{doc or method_name}-填写必填参数", call_fill)

    # 情况3：可选参数 → 追加一条
    if optional_params:
        kwargs_opt: Dict[str, Any] = {p: 1 for p in optional_params}
        kwargs_opt["authorization"] = "self.authorization"
        call_opt = f"self.api.{method_name}({_render_kwargs(kwargs_opt)})"
        _append_case(test_file, _case_name("optional", method_name, "ok"), f"{doc or method_name}-含可选参数", call_opt)

    return test_file


def generate_tests_by_spec(
    *,
    path: str,
    api_method: str,
    required: List[str] = None,
    optional: List[str] = None,
    marker: str = "Auto",
    doc: str = "",
) -> str:
    """根据接口路径推断 module/class，并生成用例。返回目标测试文件路径。"""
    required = required or []
    optional = optional or []
    module, class_name = _infer_module_and_class_from_path(path)
    return generate_single_api_tests(
        module=module,
        class_name=class_name,
        method_name=api_method,
        required_params=required,
        optional_params=optional,
        marker=marker,
        doc=doc,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="单接口用例生成工具（utils 版本）")
    # 支持位置参数：PATH API_METHOD
    parser.add_argument("path_pos", nargs="?", help="位置参数：接口路径，例如 /api/user/kids")
    parser.add_argument("api_method_pos", nargs="?", help="位置参数：已封装的方法名，例如 getKids")

    # 也支持显式参数
    parser.add_argument("--path", help="接口 URL 路径，例如 /api/user/kids")
    parser.add_argument("--api-method", dest="api_method", help="page_api 已封装的方法名，例如 getKids")
    parser.add_argument("--required", nargs="*", default=[], help="必填参数名，空格分隔")
    parser.add_argument("--optional", nargs="*", default=[], help="可选参数名，空格分隔")
    parser.add_argument("--marker", default="Auto", help="pytest 标记名，默认 Auto")
    parser.add_argument("--doc", default="", help="用例说明")

    args = parser.parse_args()
    if not args.path:
        args.path = args.path_pos
    if not args.api_method:
        args.api_method = args.api_method_pos
    if not args.path or not args.api_method:
        parser.error("缺少必要参数：请使用\n  python -m utils.single_api_test_util /api/user/kids getKids\n或\n  python -m utils.single_api_test_util --path /api/user/kids --api-method getKids")
    return args


def generate_cases(tasks):

    for t in tasks:
        out_file = generate_tests_by_spec(
            path=t["path"],
            api_method=t["api_method"],
            required=t.get("required", []),
            optional=t.get("optional", []),
            marker=t.get("marker", "Auto"),
            doc=t.get("doc", "")
        )
        print("已追加到:", out_file)


if __name__ == "__main__":
    generate_cases()



