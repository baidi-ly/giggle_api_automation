import os
PRO_PATH = os.path.dirname(os.path.abspath(__file__))


class RunConfig:
    """
    运行测试配置
    """
    # 环境信息
    baseurl = "creator.giggleacademy.com"   # 线上环境
    # baseurl = "127.0.0.1:5000"    # 本地测试
    # baseurl = "creator.qakjukl.net"     # QA环境

    # 初始化账号
    filename = "account.txt"
    # 是否https
    is_https = True
    # 超时时间
    timeout = 30


    # 日志相关
    is_log = False
    is_stack = False
    is_headers = False
    is_body = False
    is_response = False
    http_log_info = "http_info.log"
    http_log_conn = "http_conn.log"

    # 构建
    AUTH_KEY = '68C32BF7C9A0'

    # 设备ID
    DeviceId = "123456"

    # 是否配置host，普通不要动用，跑单节点的时候才能使用（平时动了会影响其他用例的执行）
    is_host = False
    passport_url = ""

    passport_aes_key = "yoJXYSzZhAOpbEFJklGtqd74X2ChTKOL"