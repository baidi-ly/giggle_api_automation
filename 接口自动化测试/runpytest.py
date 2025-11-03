import os
import pytest
import time


if __name__ =="__main__":
    now = time.strftime("%Y%m%d%H%M%S")
    path = os.getcwd()
    pathcase = path + "/test_case/"

    pathreport = path + "/report/" + 'giggle_' + str(now) + ".html"
    # 运行initUser用于初始化账号
    # pytest.main([pathcase + "/a_initUser",
    #              "-m initUser",
    #              "--html=" + pathreport,
    #              "--self-contained-html",
    #              "--reruns", "1"])
    # pytest.main([pathcase,
    #              # "-vs",
    #              # "-n 2",
    #              "-m donate",
    #              "--html=" + pathreport,
    #              "--self-contained-html",
    #              # "--reruns", "1"
    #              "--full-trace"
    #              ])

    # 2. 确保Pytest参数正确
    pytest.main([
        pathcase,
        "-m smoke1",  # 测试标记
        f"--html={pathreport}",  # 路径需用引号包裹（避免空格）
        "--self-contained-html",
        # "--full-trace"  # 可选，根据调试需求
    ])


