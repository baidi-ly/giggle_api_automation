import configparser

from pandas import DataFrame
from py._xmlgen import html
from py.xml import html
import pytest
import re
import os
import subprocess
import time
import datetime
import sys

from config import RunConfig
from test_case.page_api.admin.admin_course_api import AdminCourseApi
from test_case.page_api.admin.admin_kid_api import AdminKidApi
from test_case.page_api.book.book_api import BookApi
from test_case.page_api.user.user_api import UserApi

sys.path.append(r'..\..\..\E10自动化')
sys.path.append(os.getcwd())
sys.path.append(os.getcwd().split("接口自动化测试")[0])



account_filename = RunConfig.filename

def get_user_account(file_name=account_filename):
    '''获取人员帐号信息'''
    source_dir = os.getcwd()
    if source_dir.find("UI自动化")>-1:
        base_dir = str(source_dir).split("E10自动化")[0]
        file_path = os.path.abspath(os.path.join(base_dir, "E10自动化", "UI自动化", "testdatas", file_name))
    else:
        base_dir = os.path.dirname(__file__)
        base_dir = os.path.join(base_dir, 'test_data')
        file_path = os.path.abspath(os.path.join(base_dir, file_name))
    with open(file_path, 'r', encoding="UTF-8") as user_file:
        users = user_file.readlines()
    name = []
    username = []
    password = []
    for u in users:
        u = u.strip()
        if not u:  # 跳过空行
            continue
        parts = u.split(',')
        name.append(parts[0].strip() if len(parts) > 0 else '')
        username.append(parts[1].strip() if len(parts) > 1 else '')
        password.append(parts[2].strip() if len(parts) > 2 else '')
    # 安全获取 tenant 和 tenantKey
    tenant = ''
    tenantKey = ''
    if len(users) > 0:
        parts = users[0].strip().split(',')
        tenant = parts[4].strip() if len(parts) > 4 else ''
    if len(users) > 1:
        parts = users[1].strip().split(',')
        tenantKey = parts[4].strip() if len(parts) > 4 else ''
    return name, username, password, tenant, tenantKey

def get_user_account_all(file_name=account_filename):
    '''获取人员帐号信息'''
    base_dir = os.path.dirname(__file__)
    base_dir = os.path.join(base_dir, 'test_data')
    file_path = os.path.abspath(os.path.join(base_dir, file_name))
    with open(file_path, 'r', encoding="UTF-8") as user_file:
        users = user_file.readlines()
    name = []
    username = []
    password = []
    text = []
    depart = []
    for u in users:
        u = u.strip()
        if not u:  # 跳过空行
            continue
        parts = u.split(',')
        # 安全获取每列数据，如果列不存在则使用空字符串
        name.append(parts[0].strip() if len(parts) > 0 else '')
        username.append(parts[1].strip() if len(parts) > 1 else '')
        password.append(parts[2].strip() if len(parts) > 2 else '')
        text.append(parts[3].strip() if len(parts) > 3 else '')
        depart.append(parts[4].strip() if len(parts) > 4 else '')
    return name, username, password, text, depart


def get_base_url():
    base_url = RunConfig.baseurl
    base_url = base_url.replace("apps", "www")
    return base_url


def passedRate(summary=None):
    """计算测试通过率，使用全局统计变量"""
    global _test_stats
    try:
        # 直接使用全局统计变量
        passed = _test_stats.get('passed', 0)
        failed = _test_stats.get('failed', 0)
        error = _test_stats.get('error', 0)
        skipped = _test_stats.get('skipped', 0)
        xpassed = _test_stats.get('xpassed', 0)
        xfailed = _test_stats.get('xfailed', 0)
        
        # 调试输出
        print(f"[DEBUG] 测试统计: passed={passed}, failed={failed}, error={error}, skipped={skipped}, xpassed={xpassed}, xfailed={xfailed}")
        
        # 计算总测试数（不包括跳过的）
        total = passed + failed + error + xpassed + xfailed
        if total == 0:
            print("[DEBUG] 总测试数为0，返回0.00%")
            return "0.00%"
        
        # 计算通过率（通过的包括 passed 和 xpassed）
        success_count = passed + xpassed
        pass_rate = (success_count / total) * 100
        print(f"[DEBUG] 通过率计算: {success_count}/{total} = {pass_rate:.2f}%")
        return f'{pass_rate:.2f}%'
    except Exception as e:
        # 如果计算失败，返回默认值
        import traceback
        print(f"计算通过率时出错: {e}")
        traceback.print_exc()
        return "0.00%"

# conftest.py

tags = ''
# 存储测试统计数据
_test_stats = {
    'passed': 0,
    'failed': 0,
    'error': 0,
    'skipped': 0,
    'xpassed': 0,
    'xfailed': 0
}

def pytest_configure(config):
    """
    获取 pytest.ini 文件中所有标签
    """
    markers = config.getini("markers")
    #将markers信息赋值给上方的tags
    global tags, _test_stats
    tags = markers
    # 重置测试统计
    _test_stats = {
        'passed': 0,
        'failed': 0,
        'error': 0,
        'skipped': 0,
        'xpassed': 0,
        'xfailed': 0
    }

@pytest.hookimpl(tryfirst=True)
def pytest_runtest_logreport(report):
    """在每个测试报告时收集统计数据"""
    global _test_stats
    # 只统计 call 阶段的测试结果（setup/teardown 不统计）
    if report.when == 'call':
        if report.outcome == 'passed':
            if hasattr(report, 'wasxfail') and report.wasxfail:
                _test_stats['xpassed'] += 1
            else:
                _test_stats['passed'] += 1
        elif report.outcome == 'failed':
            if hasattr(report, 'wasxfail') and report.wasxfail:
                _test_stats['xfailed'] += 1
            else:
                _test_stats['failed'] += 1
        elif report.outcome == 'skipped':
            _test_stats['skipped'] += 1
    elif report.when == 'setup' and report.outcome == 'failed':
        # setup 阶段的失败也算作 error
        _test_stats['error'] += 1

def pytest_sessionfinish(session, exitstatus):
    """测试会话结束时重置统计（可选，用于调试）"""
    pass



@pytest.mark.optionalhook
def pytest_html_results_summary(prefix, summary, postfix):
    # 安全计算通过率，如果失败则使用默认值
    try:
        passRate = passedRate()
    except Exception as e:
        print(f"计算通过率时出错: {e}")
        passRate = "0.00%"
    
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
    # prefix.extend([html.h2(f"测试通过率:{passRate}")])
    cells = [
        html.th('用户名'),
        html.th('账号'),
        html.th('密码'),
        html.th('备注'),
        html.th('团队')
    ]
    cell_data = []
    name_turpe = get_user_account_all()
    name_list = name_turpe[0]
    uid_list = name_turpe[1]
    password_list = name_turpe[2]
    text_list = name_turpe[3]
    depart_list = name_turpe[4]
    for i in range(len(name_list)):
        cell_data.append(
            html.tr([
                html.th(name_list[i], width="100px"),
                html.th(uid_list[i], width="250px"),
                html.th(password_list[i], width="100px"),
                html.th(text_list[i], width="100px"),
                html.th(depart_list[i], width="180px")
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
        # 删除通过用例的详情，pytest-html 会自动处理空列表
        del data[:]


@pytest.mark.optionalhook
def pytest_html_results_table_header(cells):
    cells.insert(1, html.th('Description'))
    cells.insert(2, html.th('Test_nodeid'))
    cells.insert(6, html.th('failinfo'))
    cells.insert(7, html.th('tags'))
    # cells.insert(1, html.th('Time', class_='sortable time', col='time'))
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

user = UserApi()
book1 = BookApi()
admin_course = AdminCourseApi()
admin_kid = AdminKidApi()
authorization, user_id = user.get_authorization()
admin_auth, user_admin_id = admin_course.get_admin_authorization()

@pytest.fixture(scope='session')
def kid_data_session():
    '''创建测试学生'''
    try:
        # 创建测试学生
        kid_name = 'dibo_test_kid' + time.strftime("%Y%m%d%H%M%S")
        kid_id = user.createkid(authorization, kid_name)['data']['id']
    except Exception as err:
        print('创建测试学生失败，原因是：', err)
    yield kid_id, kid_name
    # 删除测试学生
    try:
        user.deletekid(authorization, kid_id)
    except Exception as err:
        print('删除测试学生失败，原因是：', err)

@pytest.fixture(scope='session', autouse=True)
def clear_test_data():
    '''session级别删除所有测试数据'''
    yield
    # 批量删除测试学生
    try:
        kids_res = admin_kid.getKidList(admin_auth, user_admin_id)['data']['content']
        for kid in kids_res:
            if kid['kidName'].startswith('dibo_test'):
                user.deletekid(authorization, kid['kidId'])
    except Exception as err:
        print('批量删除测试学生失败，原因是：', err)

    yield
    # 批量删除测试故事书
    try:
        books_res = book1.book_list(authorization, user_id)['data']['content']
        for book in books_res:
            if book['bookName'].startswith('dibo_test_book'):
                bookId = book['id']
                book1.delete_book(authorization, bookId)
    except Exception as err:
        print('批量删除测试故事书失败，原因是：', err)

@pytest.fixture(scope='session')
def get_course_ids_session():
    """获取课程详情包括版本信息"""
    try:
        # 获取顶层课程目录列表
        topcategory_res = admin_course.getAlltopcategory(admin_auth)
        for category in topcategory_res['data']:
            parentId = category['id']
            # 获取课程子目录列表
            category_res1 = admin_course.getAllsubcategory(admin_auth, parentId)
            for subcategory in category_res1['data']:
                parentId1 = subcategory['id']
                category_res2 = admin_course.getAllsubcategory(admin_auth, parentId1)
                for subcategory2 in category_res2['data']:
                    categoryId = subcategory2['id']
                    # 获取分类下所有课程
                    courselistAll = admin_course.course_listAll(admin_auth, categoryId)['data']
                    if not courselistAll:
                        continue
                    courseIds = DataFrame(courselistAll)['id'].tolist()
                    return courseIds
    except Exception as err:
        print('获取课程详情包括版本信息失败，原因是：', err)
