import configparser
from py._xmlgen import html
from py.xml import html
import pytest
import re
import os
import datetime
import sys

from config import RunConfig

sys.path.append(r'..\..\..\E10自动化')
sys.path.append(os.getcwd())
sys.path.append(os.getcwd().split("接口自动化测试")[0])

account_filename = RunConfig.filename


def get_user_account_all(file_name=account_filename):
    '''获取人员帐号信息'''
    base_dir = os.path.dirname(__file__)
    base_dir = os.path.join(base_dir, 'test_data')
    file_path = os.path.abspath(os.path.join(base_dir, file_name))
    user_file = open(file_path, 'r', encoding="UTF-8")
    users = user_file.readlines()
    name = []
    username = []
    password = []
    text = []
    for u in users:
        name.append(u.split(',')[0].strip())
        username.append(u.split(',')[1].strip())
        password.append(u.split(',')[2].strip())
        text.append(u.split(',')[3].strip())
    return name, username, password, text


def get_base_url():
    base_url = RunConfig.baseurl
    base_url = base_url.replace("apps", "www")
    return base_url


def passedRate(summary):
    reg = re.compile(r'\d+')
    passed = int(reg.findall(str(summary[3]))[0])
    failed = int(reg.findall(str(summary[9]))[0])
    error = int(reg.findall(str(summary[12]))[0])
    if passed + failed + error == 0:
        return "0.00%"
    passRate = f'{(passed/(passed + failed + error))*100}%'
    return passRate


tags = ''
def pytest_configure(config):
    """
    获取 pytest.ini 文件中所有标签
    """
    markers = config.getini("markers")
    #将markers信息赋值给上方的tags
    global tags
    tags = markers



@pytest.mark.optionalhook
def pytest_html_results_summary(prefix, summary, postfix):
    passRate = passedRate(summary)
    try:
        https_conf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'https_conf.ini')
        conf_file = configparser.ConfigParser()
        conf_file.read(https_conf_path, "utf-8")
        ht = 'https://' if RunConfig.is_https else 'http://'
    except:
        import time
        time.sleep(1)
        https_conf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'https_conf.ini')
        conf_file = configparser.ConfigParser()
        conf_file.read(https_conf_path, "utf-8")
        ht = 'https://' if RunConfig.is_https else 'http://'
    prefix.extend([html.p("测试环境: " + ht + get_base_url())])
    prefix.extend([html.h2("测试账号:")])
    cells = [
        html.th('用户名'),
        html.th('账号'),
        html.th('密码'),
        html.th('备注'),
    ]
    cell_data = []
    name_turpe = get_user_account_all()
    name_list = name_turpe[0]
    uid_list = name_turpe[1]
    password_list = name_turpe[2]
    text_list = name_turpe[3]
    for i in range(len(name_list)):
        cell_data.append(
            html.tr([
                html.th(name_list[i], width="150px"),
                html.th(uid_list[i], width="210px"),
                html.th(password_list[i], width="100px"),
                html.th(text_list[i], width="100px"),
            ])
        )
    prefix.extend([html.table([html.thead(html.tr(cells), html.tr(cell_data))], border="1")])
    prefix.extend([html.h2(f"全量测试通过率: {passRate}")])

@pytest.mark.optionalhook
def pytest_html_results_table_header(cells):
    cells.insert(2, html.th('Description'))

driver = None

@pytest.mark.optionalhook
def pytest_html_results_table_row(report, cells):
    try:
        cells.insert(1, html.td(report.description))
    except:
        print('1')


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    pytest_html = item.config.pluginmanager.getplugin('html')
    outcome = yield
    report = outcome.get_result()
    extra = getattr(report, 'extra', [])
    report = outcome.get_result()
    report.description = str(item.function.__doc__)
    report.nodeid = report.nodeid.encode("utf-8").decode("unicode_escape")
    if call.when == 'call' and report.failed == True:
        if 'AssertionError' in str(call.excinfo):
            # print('xxxxxxxxxxxxxxxxxxxxxxxxxx')
            report.extra = call.excinfo
            #print(f'report.extra:{report.extra}')
            report.__setattr__('failinfo', call.excinfo)
            # print('report.failinfo:%s' %report.failinfo)
            # print('xxxxxxxxxxxxxxxxxxxxxxxxxxx')

    if report.when == 'call' or report.when == "setup":
        xfail = hasattr(report, 'wasxfail')
        if (report.skipped and xfail) or (report.failed and not xfail):
            file_name = report.nodeid.replace("::", "_")+".png"
            '''
            screen_img = _capture_screenshot(file_name)
            if file_name:
                html = '<div><img src="data:image/png;base64,%s" alt="screenshot" style="width:600px;height:300px;" ' \
                       'onclick="window.open(this.src)" align="right"/></div>' % screen_img
                extra.append(pytest_html.extras.html(html))
            '''
        report.extra = extra
        report.description = str(item.function.__doc__)
        report.nodeid = report.nodeid.encode("utf-8").decode("unicode_escape")

    # 删除忽略后置操作的执行信息和报错信息
    if report.when == "teardown" and report.sections:
        if "teardown" in report.sections[-1][0]:
            report.sections.pop()


@pytest.mark.optionalhook
def pytest_html_results_table_html(report, data):
    """删除通过用例的测试报告内容"""
    if report.passed:
        data =data
        del data[:]
        data.append(html.div('No log output captured.', class_='empty log'))


@pytest.mark.optionalhook
def pytest_html_results_table_header(cells):
    cells.insert(1, html.th('Description'))
    cells.insert(2, html.th('Test_nodeid'))
    cells.insert(6, html.th('failinfo'))
    cells.insert(7, html.th('tags'))
    cells.pop(2)

@pytest.mark.optionalhook
def pytest_html_results_table_row(report, cells):
    # print(report)
    # print(dir(report))
    # 获取pytest.ini中的配置信息
    # print(a)
    #遍历tags按:分割，取第一个值,并返回新的数组
    tag_ini = [i.split(':')[0] for i in tags]
    # 获取report中的keywords的所有key值
    tag_report = list(report.keywords.keys())
    # 找出tag_ini和tag_report的交集,以逗号分割
    try:
        tags_new = ','.join(list(set(tag_ini).intersection(set(tag_report))))
    except:
        # 此处用例如果没找到标签表示未在pytest.ini中配置标签，直接返回空
        tags_new = ''
    try:
        cells.insert(1, html.td(report.description))
    except:
        print(f'出错文件位置{(report.location)[0]}')
        print('-------------------------------------------')
        print(f'出错原因{report.longreprtext}')
    cells.insert(2, html.td(report.nodeid))
    if 'AssertionError' in report.longreprtext:
        log = report.longreprtext
        failinfo = re.findall(r'AssertionError:(.*)?', log)
        cells.insert(6, html.td(f'AssertionError:{failinfo}'))
    else:
        if report.longreprtext == '':
            cells.insert(6, html.td('通过'))
        else:
            cells.insert(6, html.td('非断信息失败导致的接口不通过'))
            # cells.insert(6, html.td(report.failinfo))
    # cells.insert(1, html.td(datetime.utcnow(), class_='col-time'))
    cells.insert(7, html.td(tags_new))
    cells.pop(2)


@pytest.mark.optionalhook
def pytest_html_results_table_row(report, cells):
    """收集并检测是否有错误信息影响整体用例运行"""
    fail_locations = os.environ.get("FAIL_LOCATION", "").split(";")
    fail_reasons = os.environ.get("FAIL_REASON", "").split(";")
    now = datetime.datetime.now()
    date_string = now.strftime("%y/%m/%d-%H:%M")

    try:
        cells.insert(1, html.td(report.description))
    except:
        # 使用正则表达式从报错信息中提取详细报错
        fail_location = (report.location)[0]
        fail_reason = re.search(r"E.*Error.*", report.longreprtext)
        if fail_reason is not None:
            fail_reason = fail_reason.group(0)
        else:
            fail_reason = ""

        fail_locations.append(fail_location)
        fail_reasons.append(fail_reason)

    # 写入文件
    with open("prerun_results.txt", "w") as f:
        if len(fail_locations) == 0:
            f.write("checkResult=%s" % '<span style="color:green;">本次预检测成功！</span>' + "\n")
            f.write("title=%s" % '成功' + "\n")
            f.write("time=%s" % date_string)
        else:
            fail_locations = [loc for loc in fail_locations if loc]
            fail_reasons = [reason for reason in fail_reasons if reason]
            if len(fail_locations) > 0:
                error_list = []
                for i in range(len(fail_locations)):
                    error_str = "<b>出错位置（%d）：</b>%s<br><b>出错原因：</b>%s<hr>" % (i + 1, fail_locations[i], fail_reasons[i])
                    error_list.append(error_str)
                error_string = "".join(error_list)
                f.write("checkResult=%s" % error_string + "\n")
                f.write("title=%s" % '失败' + "\n")
            else:
                f.write("checkResult=%s" % '<span style="color:green;">本次预检测成功！</span>' + "\n")
                f.write("title=%s" % '成功' + "\n")
            f.write("time=%s" % date_string)
            os.environ["FAIL_LOCATION"] = ';'.join(fail_locations)
            os.environ["FAIL_REASON"] = ';'.join(fail_reasons)

import os
# 自定义 fixture：将装饰器应用到接口函数
@pytest.fixture(autouse=True)
def add_interface_description_to_request_header(request):
    interface_function = request.node
    if interface_function and hasattr(interface_function, "_obj") and callable(interface_function._obj):
        des = interface_function._obj.__doc__

        if not des:
            interface_description = "未提供用例描述"  # 如果没有描述，默认使用未提供接口描述
        else:
            interface_description = des
        os.environ.update({"nodeid_des": interface_function.nodeid})
        os.environ.update({"case_des": interface_description})
    yield
    os.environ.update({"nodeid_des": ""})
    os.environ.update({"case_des": ""})