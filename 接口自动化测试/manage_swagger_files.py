#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Swagger文件管理脚本
用于查看、清理和管理下载的原始swagger文件
"""

import os
import json
import glob
from datetime import datetime

def list_swagger_files(swagger_dir: str = "test_data"):
    """列出所有swagger相关文件"""
    print("=== Swagger文件列表 ===")
    
    # 查找所有原始swagger文件
    raw_files = glob.glob(os.path.join(swagger_dir, "**/temp/swagger_raw_*.json"), recursive=True)
    raw_files.sort(key=os.path.getmtime, reverse=True)
    
    print(f"\n原始下载文件 ({len(raw_files)} 个):")
    for file_path in raw_files:
        if os.path.exists(file_path):
            stat = os.stat(file_path)
            size = stat.st_size / 1024  # KB
            mtime = datetime.fromtimestamp(stat.st_mtime)
            print(f"  {file_path}")
            print(f"    大小: {size:.1f} KB, 修改时间: {mtime}")
    
    # 查找处理后的swagger文件
    fixed_file = os.path.join(swagger_dir, "swagger", "swagger_fixed.json")
    if os.path.exists(fixed_file):
        stat = os.stat(fixed_file)
        size = stat.st_size / 1024  # KB
        mtime = datetime.fromtimestamp(stat.st_mtime)
        print(f"\n处理后的文件:")
        print(f"  {fixed_file}")
        print(f"    大小: {size:.1f} KB, 修改时间: {mtime}")
        
        # 显示swagger文件信息
        try:
            with open(fixed_file, 'r', encoding='utf-8') as f:
                swagger_data = json.load(f)
            print(f"    版本: {swagger_data.get('info', {}).get('version', 'Unknown')}")
            print(f"    API数量: {len(swagger_data.get('paths', {}))}")
        except Exception as e:
            print(f"    读取文件信息失败: {e}")

def clean_old_files(swagger_dir: str = "test_data", keep_days: int = 7):
    """清理旧的原始swagger文件"""
    print(f"\n=== 清理 {keep_days} 天前的文件 ===")
    
    raw_files = glob.glob(os.path.join(swagger_dir, "**/temp/swagger_raw_*.json"), recursive=True)
    current_time = datetime.now().timestamp()
    cutoff_time = current_time - (keep_days * 24 * 60 * 60)
    
    deleted_count = 0
    for file_path in raw_files:
        if os.path.exists(file_path):
            mtime = os.path.getmtime(file_path)
            if mtime < cutoff_time:
                try:
                    os.remove(file_path)
                    print(f"已删除: {file_path}")
                    deleted_count += 1
                except Exception as e:
                    print(f"删除失败 {file_path}: {e}")
    
    print(f"共删除了 {deleted_count} 个文件")

def show_latest_info(swagger_dir: str = "test_data"):
    """显示最新的swagger文件信息"""
    print("\n=== 最新Swagger信息 ===")
    
    fixed_file = os.path.join(swagger_dir, "swagger", "swagger_fixed.json")
    if not os.path.exists(fixed_file):
        print("未找到处理后的swagger文件")
        return
    
    try:
        with open(fixed_file, 'r', encoding='utf-8') as f:
            swagger_data = json.load(f)
        
        info = swagger_data.get('info', {})
        print(f"标题: {info.get('title', 'Unknown')}")
        print(f"版本: {info.get('version', 'Unknown')}")
        print(f"描述: {info.get('description', 'No description')}")
        print(f"主机: {swagger_data.get('host', 'Unknown')}")
        print(f"基础路径: {swagger_data.get('basePath', 'Unknown')}")
        print(f"API路径数量: {len(swagger_data.get('paths', {}))}")
        
        # 显示一些API示例
        paths = list(swagger_data.get('paths', {}).keys())
        if paths:
            print(f"\nAPI路径示例 (前10个):")
            for path in paths[:10]:
                print(f"  {path}")
            if len(paths) > 10:
                print(f"  ... 还有 {len(paths) - 10} 个API")
                
    except Exception as e:
        print(f"读取swagger文件失败: {e}")

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Swagger文件管理工具')
    parser.add_argument('--list', '-l', action='store_true', help='列出所有swagger文件')
    parser.add_argument('--clean', '-c', type=int, metavar='DAYS', help='清理指定天数前的文件')
    parser.add_argument('--info', '-i', action='store_true', help='显示最新swagger文件信息')
    parser.add_argument('--dir', '-d', default='test_data', help='swagger文件目录')
    
    args = parser.parse_args()
    
    if args.list:
        list_swagger_files(args.dir)
    elif args.clean is not None:
        clean_old_files(args.dir, args.clean)
    elif args.info:
        show_latest_info(args.dir)
    else:
        # 默认显示所有信息
        list_swagger_files(args.dir)
        show_latest_info(args.dir)

if __name__ == '__main__':
    main()
