import argparse
import json
import os

from utils.init_swagger import logger, init_swagger

if __name__ == '__main__':
    ''' 前置需要对装饰器进行替换'''
    # 目标API列表
    file_path: str = os.path.join("test_data", "api_difference.json")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"未找到差异文件: {file_path}，请先运行比较脚本生成")
    with open(file_path, "r", encoding="utf-8") as f:
        target_apis = json.load(f)['apis']

    parser = argparse.ArgumentParser(description='初始化Swagger文档')
    parser.add_argument('--url', '-u', default='https://creator.qakjukl.net/swagger-resources/v2/api-docs',
                        help='Swagger文档的URL')
    parser.add_argument('--dir', '-d', default=os.path.abspath(
        os.path.join(os.path.dirname(__file__), 'test_data')),
                        help='Swagger文档目录')
    parser.add_argument('--no-backup', '-n', action='store_true',
                        help='不备份原始文档（默认会保留原始下载文件）')

    args = parser.parse_args()

    # 初始化swagger文档 - 不传递target_apis，保存所有API
    swagger_success = init_swagger(args.url, args.dir, not args.no_backup, [])
    if swagger_success:
        logger.info("Swagger文档初始化成功！")
    else:
        logger.warning("Swagger文档初始化失败，但继续执行...")
        # 不直接退出，继续执行后续步骤