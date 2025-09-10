import os
import pytest
import time


if __name__ =="__main__":
    now = time.strftime("%Y%m%d%H%M%S")
    path = os.getcwd()
    pathcase = path + "/test_case/"

    pathreport = path + "/report/" + str(now) + ".html"
    # 运行initUser用于初始化账号
    # pytest.main([pathcase + "/a_initUser",
    #              "-m initUser",
    #              "--html=" + pathreport,
    #              "--self-contained-html",
    #              "--reruns", "1"])
    pytest.main([pathcase,
                 # "-vs",
                 # "-n 2",
                 "-m pendingRelease",
                 "--html=" + pathreport,
                 "--self-contained-html",
                 # "--reruns", "1"
                 "--full-trace"
                 ])


