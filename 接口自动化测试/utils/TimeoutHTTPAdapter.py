from requests.adapters import HTTPAdapter
from requests.exceptions import ReadTimeout
import os

import time
import re
from urllib.parse import quote
from requests.models import Response
from config import RunConfig
from utils.myLogger import MyLogger

old_path = os.getcwd()
is_https = RunConfig.is_https
is_log = RunConfig.is_log == True


import inspect


def get_caller_function_info():
    # 获取调用者的栈帧信息
    caller_frame = inspect.stack()[1]

    # 获取调用者的上级函数名称
    caller_function_name = caller_frame.function

    # 获取上级函数的源代码
    caller_source_lines, _ = inspect.getsourcelines(caller_frame.frame.f_globals[caller_function_name])

    # 获取上级函数的描述，通常在函数定义的下一行添加注释
    caller_description = None
    for line in caller_source_lines:
        if line.strip().startswith('#'):
            caller_description = line.strip('#').strip()
            break

    return caller_function_name, caller_description

class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = int(RunConfig.timeout)  # 单位是秒
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        if is_log:
            self.http_log_info = RunConfig.http_log_info  # http输出信息日志。存放正常的接口信息
            self.http_log_conn = RunConfig.http_log_conn # http连接超时日志。存放正常的接口信息
            self.is_headers = RunConfig.is_headers == True  # http_info*.log中是否记录request.header
            self.is_body = RunConfig.is_body == True  # http_info*.log中是否记录request.body
            self.is_response = RunConfig.is_response == True  # http_info*.log中是否记录response
            self.is_stack = RunConfig.is_stack == True  # http_info*.log中是否记录response
            if self.is_stack:
                self.my_logger = MyLogger(self.http_log_info)
            else:
                self.my_logger = MyLogger(self.http_log_info, fmt='%(asctime)s: %(message)s')
        super().__init__(*args, pool_connections=20, pool_maxsize=20, pool_block=True, **kwargs)

    def send(self, request, **kwargs):
        doc = os.environ.get('api_doc')
        doc = doc.split("\n")[0] if doc else ""
        timeout = kwargs.get("timeout")
        kwargs["verify"] = False
        if timeout is None:
            kwargs["timeout"] = self.timeout
        if not is_https:
            request.url = request.url.replace('+', '%20')
            if RunConfig.is_host and RunConfig.passport_url != "" and "/appnew/login/appLogin" in request.url:
                request.url = request.url.replace(RunConfig.baseurl, RunConfig.passport_url)
            else:
                request.url = request.url.replace("https://", "http://")

        case_des = os.environ.get("case_des","").strip()
        nodeid_des = os.environ.get("nodeid_des", "")

        request.headers['X-Case-Description'] = quote(case_des)
        request.headers['X-Interface-Description'] = quote(doc)
        request.headers['x-access-NodeId'] = nodeid_des
        request.headers['t'] = 1
        # 如果接口超时，则自定义返回内容，告诉大家这个接口超时了
        request_duration = 0
        try:
            start_time = time.time()
            response = super().send(request, **kwargs)
            # 如果响应码不为5xx，4xx，则记录接口响应时间
            if response.status_code < 500:
                end_time = time.time()
                request_duration = end_time - start_time
                # 对request_duration保留两位小数
                request_duration = round(request_duration, 2)
                pathUrl = response.url
                print(f'接口：{pathUrl}, 响应时间：{request_duration}秒')
        except ReadTimeout:
            response = Response()
            response.status_code = 500
            response.headers = ""
            request_headers_str = str(request.headers)
            ETEAMSID_list = re.findall("'ETEAMSID=(.*?)'", request_headers_str)
            response.reason = {"messsage": f"报错原因:接口:{request.url},响应超过:{str(self.timeout) }秒,"
                                           f" 发生问题客户端时间:{time.strftime('%Y-%m-%d %H:%M:%S')},ETEAMSID={ETEAMSID_list}"}

        if request.url.endswith("/upload") and (
            response.status_code != 200 or ('"code":200' not in response.text and '"code":101' not in response.text)):
            request.body = ""
            response_data = "上传附件失败，具体原因不去确定, 发生问题客户端时间：" + time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            response_data = response.text
        info = '\n--url:{};\n--headers:{};\n--body:{};\n--response:{};\n--request.headers:{};\n;\n接口响应时间:{}秒'.format(
            request.url,
            response.headers,
            request.body or ' ',
            response_data or response.reason,
            request.headers,
            request_duration
        )
        exc_info = '\n--[接口异常信息开始]--{}\n--[接口异常信息结束]--\n'.format(info)
        is_login_api ='/login/appLogin' in request.url # 是否是登录接口
        if response.status_code == 200:
            if is_log:
                info_headers = '\n--headers:{};'.format(response.headers) if self.is_headers else ''
                info_body = '\n--body:{};'.format(request.body) if self.is_body else ''
                info_response = '\n--response:{};'.format(response_data) if self.is_response else ''
                request_headers = '\n--request.headers:{};'.format(request.headers) if self.is_response else ''
                normal_info = '\n--url:{};{}{}{}{}'.format(request.url, info_headers, info_headers, info_body,
                                                         info_response,request_headers)
            else:
                normal_info = None
            response_text = response.text
            if response_text:
                try:
                    res = response.json()
                    # 判断开放平台的错误
                    if isinstance(res, dict):
                        try:
                            if "errcode" in res.get("message", {}):
                                try:
                                    value = int(res.get("message", {}).get("errcode", 1))
                                    if value != 0 and value != 200:
                                        print(exc_info)
                                except:
                                    print(exc_info)
                        except:
                            pass
                    if is_log and not is_login_api:
                        self.my_logger.logger.info(normal_info)
                except ValueError:
                    if is_log and not is_login_api:
                        self.my_logger.logger.info(normal_info)
            elif is_log and not is_login_api:
                self.my_logger.logger.info(normal_info)
        else:
            if response.status_code == 302:
                return response
            try:
                # 去掉这个url的错误打印
                if "/api/baseserver/layout?" not in request.url and "/papi/tenant_manage/login/login" not in request.url:
                    print(exc_info)
            except:
                print(exc_info)
        # os.environ.clear()
        return response

