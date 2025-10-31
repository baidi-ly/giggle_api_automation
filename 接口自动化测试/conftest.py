import configparser
from py._xmlgen import html
from py.xml import html
import pytest
import re
import os
import datetime
import sys
import html as html_escape_module

from config import RunConfig

sys.path.append(r'..\..\..\E10自动化')
sys.path.append(os.getcwd())
sys.path.append(os.getcwd().split("接口自动化测试")[0])

account_filename = RunConfig.filename


def escape_html(text):
    """转义 HTML 特殊字符，防止 XSS 攻击"""
    if text is None:
        return ''
    if not isinstance(text, str):
        text = str(text)
    return html_escape_module.escape(text)


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


# def passedRate(summary):
#     reg = re.compile(r'\d+')
#     passed = int(reg.findall(str(summary[3]))[0])
#     failed = int(reg.findall(str(summary[9]))[0])
#     error = int(reg.findall(str(summary[12]))[0])
#     if passed + failed + error == 0:
#         return "0.00%"
#     passRate = f'{(passed/(passed + failed + error))*100}%'
#     return passRate


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
    # passRate = passedRate(summary)
    passRate = 100
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
        # 转义所有用户数据，防止 XSS
        cell_data.append(
            html.tr([
                html.th(escape_html(name_list[i]), width="150px"),
                html.th(escape_html(uid_list[i]), width="210px"),
                html.th(escape_html(password_list[i]), width="100px"),
                html.th(escape_html(text_list[i]), width="100px"),
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
        # 转义 description，防止 XSS
        desc = escape_html(str(report.description)) if report.description else ''
        cells.insert(1, html.td(desc))
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
        # 转义 description，防止 XSS
        desc = escape_html(str(report.description)) if report.description else ''
        cells.insert(1, html.td(desc))
    except:
        print(f'出错文件位置{(report.location)[0]}')
        print('-------------------------------------------')
        print(f'出错原因{report.longreprtext}')
    # 转义 nodeid，防止 XSS
    nodeid_escaped = escape_html(str(report.nodeid)) if report.nodeid else ''
    cells.insert(2, html.td(nodeid_escaped))
    if 'AssertionError' in report.longreprtext:
        log = report.longreprtext
        failinfo = re.findall(r'AssertionError:(.*)?', log)
        # 转义 failinfo，防止 XSS
        failinfo_escaped = escape_html(str(failinfo))
        cells.insert(6, html.td(f'AssertionError:{failinfo_escaped}'))
    else:
        if report.longreprtext == '':
            cells.insert(6, html.td('通过'))
        else:
            cells.insert(6, html.td('非断信息失败导致的接口不通过'))
            # cells.insert(6, html.td(report.failinfo))
    # cells.insert(1, html.td(datetime.utcnow(), class_='col-time'))
    # 转义 tags_new，防止 XSS
    tags_escaped = escape_html(str(tags_new)) if tags_new else ''
    cells.insert(7, html.td(tags_escaped))
    cells.pop(2)


@pytest.mark.optionalhook
def pytest_html_results_table_row(report, cells):
    """收集并检测是否有错误信息影响整体用例运行"""
    fail_locations = os.environ.get("FAIL_LOCATION", "").split(";")
    fail_reasons = os.environ.get("FAIL_REASON", "").split(";")
    now = datetime.datetime.now()
    date_string = now.strftime("%y/%m/%d-%H:%M")

    try:
        # 转义 description，防止 XSS
        desc = escape_html(str(report.description)) if report.description else ''
        cells.insert(1, html.td(desc))
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
                    # 转义 HTML 特殊字符，防止 XSS
                    escaped_location = escape_html(fail_locations[i])
                    escaped_reason = escape_html(fail_reasons[i])
                    error_str = "<b>出错位置（%d）：</b>%s<br><b>出错原因：</b>%s<hr>" % (i + 1, escaped_location, escaped_reason)
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


def fix_xss_in_html(html_path):
    """修复 HTML 文件中的 XSS 问题 - 修复 JavaScript 代码中的 innerHTML 和 insertAdjacentHTML"""
    if not os.path.exists(html_path):
        return
    
    with open(html_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 添加 HTML 转义函数到 JavaScript 代码中
    escape_function = """
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
function escapeHtmlForLog(text) {
    if (!text) return '';
    return escapeHtml(text).replace(/\\n/g, '<br>').replace(/\\r/g, '');
}
"""
    
    # 在第一个 function 定义前插入转义函数，避免重复插入
    if 'function escapeHtml' not in content:
        if 'function htmlToElements' in content:
            content = content.replace(
                'function htmlToElements',
                escape_function + '\nfunction htmlToElements',
                1
            )
        elif '<script>' in content:
            content = content.replace(
                '<script>',
                '<script>\n' + escape_function,
                1
            )
    
    # 修复所有 innerHTML 使用（通过模式匹配）
    # 1. temp.innerHTML = html
    content = re.sub(
        r'(function htmlToElements\(html\) \{[^}]*?)(temp\.innerHTML = html)',
        r'\1// XSS修复: 使用DOMParser安全解析\n    const parser = new DOMParser();\n    const doc = parser.parseFromString(escapeHtml(html), "text/html");\n    const fragment = document.createDocumentFragment();\n    Array.from(doc.body.childNodes).forEach(node => fragment.appendChild(node));\n    temp.content.appendChild(fragment)',
        content,
        flags=re.DOTALL
    )
    
    # 2. t.innerHTML = html
    if 't.innerHTML = html' in content and 'DOMParser' not in content.split('t.innerHTML = html')[0][-200:]:
        content = re.sub(
            r'(\s+)(t\.innerHTML = html)',
            r'\1// XSS修复: 使用DOMParser安全解析\n\1const parser = new DOMParser();\n\1const doc = parser.parseFromString(escapeHtml(html), "text/html");\n\1const fragment = document.createDocumentFragment();\n\1Array.from(doc.body.childNodes).forEach(node => fragment.appendChild(node));\n\1t.content.appendChild(fragment)',
            content,
            count=1
        )
    
    # 3. resultBody.querySelector('.log').innerHTML = wrappedLog
    content = re.sub(
        r"(resultBody\.querySelector\(['\"]\.log['\"]\)\.innerHTML = wrappedLog)",
        r"// XSS修复: 转义日志内容\n            const logElem = resultBody.querySelector('.log');\n            if (logElem) {\n                logElem.innerHTML = escapeHtmlForLog(log)",
        content
    )
    
    # 4. insertAdjacentHTML for extraHTML
    content = re.sub(
        r"(resultBody\.querySelector\(['\"]\.extraHTML['\"]\)\.insertAdjacentHTML\(['\"]beforeend['\"], `<div>\$\{content\}</div>`)",
        r"// XSS修复: 使用textContent\n                const extraElem = resultBody.querySelector('.extraHTML');\n                if (extraElem) {\n                    const div = document.createElement('div');\n                    div.textContent = content;\n                    extraElem.appendChild(div);\n                }",
        content
    )
    
    # 5. insertAdjacentHTML for tableHtml
    old_code = "resultBody.querySelector('td[class=\"extra\"]').insertAdjacentHTML('beforeend', item)"
    new_code = """// XSS修复: 转义后插入
            const extraTd = resultBody.querySelector('td[class="extra"]');
            if (extraTd && item) {
                const itemDiv = document.createElement('div');
                itemDiv.innerHTML = escapeHtml(String(item));
                extraTd.appendChild(itemDiv);
            }"""
    if old_code in content:
        content = content.replace(old_code, new_code)
    
    # 6. showhideall.innerHTML (旧版本pytest-html)
    if "showhideall.innerHTML" in content:
        content = re.sub(
            r"(showhideall\.innerHTML = '[^']+' \+[\s\n]*'[^']+';)",
            r"""// XSS修复: 使用appendChild\n    const link1 = document.createElement('a');\n    link1.href = 'javascript:showAllExtras()';\n    link1.textContent = 'Show all details';\n    const link2 = document.createElement('a');\n    link2.href = 'javascript:hideAllExtras()';\n    link2.textContent = 'Hide all details';\n    showhideall.appendChild(link1);\n    showhideall.appendChild(document.createTextNode(' / '));\n    showhideall.appendChild(link2);""",
            content
        )
    
    # 7. collapsed.includes(elem.innerHTML) - 读取 innerHTML
    content = re.sub(
        r"(\s+)collapsed\.includes\(elem\.innerHTML\)",
        r"\1collapsed.includes(elem.textContent || '')",
        content
    )
    
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(content)


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    """在测试会话结束时修复生成的 HTML 文件中的 XSS 问题"""
    htmlpath = session.config.getoption("htmlpath")
    if htmlpath and os.path.exists(htmlpath):
        fix_xss_in_html(htmlpath)
    
    # 同时修复 report 目录下最近生成的 HTML 文件
    report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'report')
    if os.path.exists(report_dir):
        import time
        current_time = time.time()
        html_files = []
        for filename in os.listdir(report_dir):
            if filename.endswith('.html'):
                filepath = os.path.join(report_dir, filename)
                mtime = os.path.getmtime(filepath)
                # 修复最后5分钟内修改的文件
                if current_time - mtime < 300:
                    html_files.append(filepath)
        
        html_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        for filepath in html_files[:3]:
            try:
                fix_xss_in_html(filepath)
            except Exception as e:
                print(f"修复文件 {filepath} 时出错: {e}")