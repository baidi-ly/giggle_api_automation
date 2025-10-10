from utils.api_scanner import ApiScanner
from utils.init_swagger import logger

logger.info("开始扫描接口文档并对比API方法...")
scanner = ApiScanner()
missing_apis = scanner.run_scan()

if missing_apis:
    logger.info(f"发现 {len(missing_apis)} 个缺失的接口，已保存到 api_difference.json")
else:
    logger.info("所有接口都已实现！")