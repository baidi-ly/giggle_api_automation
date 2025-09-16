# eteams功能自动化测试

### 特点

* 全局配置浏览器启动/关闭。
* 测试用例运行失败自动截图。
* 测试用例运行失败可以重跑。

### 安装

```shell
$ pip install -r requirements.txt
```

注：安装```requirements.txt```指定依赖库的版本，这是经过测试的，有时候新的版本可会有错。

### 目录说明

```shell
report/: 存放测试报告
test_case/: 存放测试用例
    page_api/: 存放测试接口
	--base_api.py 
    	其他模块以模块名称命名，继承base_api,如signupApi(Page_API)。
    book/: 书籍相关api
    test_book_case/: 书籍相关的测试用例
        命名规则: test_模块名称_功能名称_api。如：test_system_api.py（如：test_模块名称_功能名称_*_api.py，*号长度不限）
        最新基线测试用例 @pytest.mark.pendingRelease
        冒烟测试用例 @pytest.mark.smoke
    test_data: 存放测试过程中需要使用的测试数据
.gitignore: 不需要提交的文件类型配置。
conf.ini：自动化配置，每次运行需要确认配置。
conftest.py: 全局配置，各模块共享配置。
pytest.ini: 对mark进行声明，解决PytestUnknownMarkWarning提示。
runpytest.py: 运行入口，可通过pytest -k -m等配置筛选用例。
```

### 配置

在 `conf.ini` 文件配置

```shell
baseurl = creator.qakjukl.net
通过baseurl指定测试环境
```

### 运行

```shell
$ python runpytest.py 
```


### 测试环境选择
```
conf.ini文件中修改base_url
baseurl = "creator.giggleacademy.com"   # 线上环境
baseurl = "127.0.0.1:5000"    # 本地测试
baseurl = "creator.qakjukl.net"     # QA环境
```

### 单接口生成规则
```
- **是否必填**: 缺失、为空、null
- **数据格式**: 校验参数类型（整数、浮点数、布尔值、列表、字典）、格式不正确的如特殊字符、邮箱、手机号、日期、emoji、枚举、正则
- **边界值**: 整数（数据大小）、字符串（字符长度）、列表（单值、多值）
- **场景异常**: 不存在的 ruleids
- **权限**: 身份验证（未登录、过期的 token、不存在的 token）、角色权限（权限不足、不同角色访问资源校验）
- **安全**: SQL 注入、XSS 攻击、CSRF 攻击
```