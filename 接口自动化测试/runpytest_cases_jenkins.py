import sys, os
import time
import requests
import pytest
import json

from config import RunConfig

function_path = os.path.abspath('.')
function_path = function_path
function_path1 = function_path.replace("接口自动化测试","")
function_path2 = os.path.join(function_path,"test_case")
print("function_path2",function_path2)
sys.path.append(function_path)
sys.path.append(function_path1)
sys.path.append(function_path2)



#
args = sys.argv[1:]
# # 获取测试用例集，字符串，用逗号隔开
cases = args[0]

# print("list_case:",list_case)
# 获取账号信息
account = args[1]
account = account.encode().decode("unicode_escape")
list_account = [i.split("\n") for i in account.split(",")]
list_del = []
for account in list_account:
    list_data = [ i for i in account if i]
    account_data = ",".join(list_data)
    list_del.append(account_data)
account_input = "\n".join(list_del)
# print(account_input)
file_name = "account.txt"
path = os.path.abspath('.')
RunConfig.filename = file_name
account_path = path + f'\\test_data\\'+ file_name
with open(account_path,"w",encoding="utf-8") as f:
    f.write(account_input)
# # 获取运行环境信息
base_url = args[2]
#
is_https = args[3]
case_id = args[4]
task_id = args[5]

rerun = 0
if len(args)>6:
    try:
        rerun = int(args[6])
    except:
        pass
timeout = None
if len(args)>7:
    timeout = args[7]

# # case_id = "16716011221401005"
print("运行环境信息:",base_url,is_https)

if __name__ =="__main__":
    try:
        # 获取用例
        if cases == "all":
            url = "http://10.12.251.117:8888/report/repeat/all/get/cases"
            data = {"case_id": case_id}
            analysis_res = requests.post(url=url, data=json.dumps(data)).json()
            list_case = analysis_res.get("list_case")
        else:
            list_case = cases.split(",")
        list_case = choose_vaild_cases(list_case)
        print("当前运行用例：", list_case)
        if len(list_case)<1:
            raise ValueError("没有有效的测试用例！")
        path = os.getcwd()
        dir_path = path + "/JenkinsReport"
        # 删除3天之前的报告
        all_files = os.listdir(dir_path)
        files = [dt for dt in all_files if os.path.isfile(os.path.join(dir_path, dt)) and filter_date_file(dt)]
        if files:
            for file_html in files:
                file_del_path = os.path.join(dir_path,file_html)
                os.remove(file_del_path)
        report_name = time.strftime("report%Y%m%d%H%M%S.html")
        pathreport = path + "/JenkinsReport/{0}".format(report_name)

        RunConfig.baseurl = base_url
        if timeout:
            print("timeout", timeout)
            RunConfig.timeout = timeout
        if is_https.strip() == "True":
            RunConfig.is_https = True
        else:
            RunConfig.is_https = False
            # print("http:",is_https)
        list_ex = [f'./{i}' for i in list_case]
        list_ex.extend(["--html=" + pathreport,"--self-contained-html"])
        # print(list_ex)
        if rerun > 0:
            print(f"设置重试次数：{rerun}")
            list_ex.extend(["--reruns", f"{rerun}"])
        pytest.main(list_ex)
        # 分析测试报告，并将结果回传给数据库
        new_file_path = os.path.join(path,"JenkinsReport")
        page = ReportAnalysis(pathreport, "重试失败用例", new_file_path)
        page.open_html()
        page.get_results_by_module()
        result = page.result_dic_module
        print("report_name:",report_name)
        url = 'http://10.12.251.117:8888/auth/report/analysis/repeat/update'
        data = {"result_dic_module": result,"report_name":report_name,"case_id":case_id,"task_id":task_id}
        analysis_res = requests.post(url=url, data=json.dumps(data)).json()
        print("发送平台数据库，返回：",analysis_res)
        if analysis_res["code"] != 200:
            print("数据传给服务器数据库失败：", analysis_res["msg"])
    except Exception as e:
        print(e)
        url = 'http://10.12.251.117:8888/jenkins/task/update'
        data = {
            "dict_update": {"status": "运行失败"},
            "task_id": task_id
        }
        analysis_res = requests.post(url=url, data=json.dumps(data)).json()
        print("标记任务失败，返回：", analysis_res)




