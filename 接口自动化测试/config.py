import os
PRO_PATH = os.path.dirname(os.path.abspath(__file__))


class RunConfig:
    """
    运行测试配置
    """
    # 环境信息
    # baseurl = "creator.giggleacademy.com"   # 线上环境
    # baseurl = "127.0.0.1:5000"    # 本地测试
    # baseurl = "creator.giggleacademy.com"     # 线上-creator站点
    baseurl = "creator.qakjukl.net"     # QA-creator站点
    admin_baseurl = 'admin.qakjukl.net'     # QA-admin站点admin-ga.toolsapple.net/
    # admin_baseurl = 'admin-ga.toolsapple.net'
    official_baseurl = 'qakjukl.net'     # QA-官网



    # 初始化账号
    filename = "account.txt"
    # 是否https
    is_https = True
    # 超时时间
    timeout = 120


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

    # 当前版本号
    VersionId = 'V1.19.0'

    # 是否配置host，普通不要动用，跑单节点的时候才能使用（平时动了会影响其他用例的执行）
    is_host = False
    passport_url = ""

    passport_aes_key = "yoJXYSzZhAOpbEFJklGtqd74X2ChTKOL"
    # 过期token
    expired_token  = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aW1lU3RhbXAiOjE3NjI3NTM2NDA2NjIsInVzZXJJZCI6NzI1Mzk0MjYzODA2MDIxLCJlbWFpbCI6ImJkMjI0MzRAMTYzLmNvbSIsInVzZXJuYW1lIjoiYmQyMjQzNEAxNjMuY29tIn0.lJDYVc1sVQHhKQ8deW_97vNM66aIVFx7LvylJ7dWbAo'