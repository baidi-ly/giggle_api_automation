from utils.api_scanner import ApiScanner
from utils.init_swagger import logger

logger.info("寮€濮嬫壂鎻忔帴鍙ｆ枃妗ｅ苟瀵规瘮API鏂规硶...")
scanner = ApiScanner()
missing_apis = scanner.run_scan()

if missing_apis:
    logger.info(f"鍙戠幇 {len(missing_apis)} 涓己澶辩殑鎺ュ彛锛屽凡淇濆瓨鍒?api_difference.json")
else:
    logger.info("鎵€鏈夋帴鍙ｉ兘宸插疄鐜帮紒")