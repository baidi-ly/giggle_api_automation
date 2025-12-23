import sys
import os
from time import strftime

from pandas import DataFrame

from test_case.page_api.admin.admin_course_api import AdminCourseApi
from test_case.page_api.admin.admin_curriculum_api import AdminCurriculumApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.admin
@pytest.mark.adminCurriculum
class TestAdminCurriculum:

    def setup_class(self):
        self.admin_curriculum = AdminCurriculumApi()
        self.authorization = self.admin_curriculum.get_authorization()[0]
        self.admin_auth = self.admin_curriculum.get_admin_authorization()[0]

        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.fixture(scope="class")
    def create_curriculum_path_fixtures(self):
        # 创建课程路径
        pathName = 'dibo_test_curriculum_path' + self.now
        create_res = self.admin_curriculum.create_curriculum_path(self.admin_auth, pathName=pathName)
        path_id = create_res['data']['id']

        yield path_id

        # 删除课程路径
        delete_res = self.admin_curriculum.delete_curriculum_path(self.admin_auth, path_id)
        assert delete_res['message'] == 'success'


    @pytest.mark.release
    def test_admin_curriculum_positive_create_curriculum_path(self):
        """课程路径 - 增删改查校验"""
        # 创建课程路径
        pathName = 'dibo_test_curriculum_path' + self.now
        create_res = self.admin_curriculum.create_curriculum_path(self.admin_auth, pathName=pathName)
        path_id = create_res['data']['id']
        # 创建课程路径后，查询路径列表，验证新增成功
        list_res2 = self.admin_curriculum.curriculum_path_list(self.admin_auth)['data']
        path_ids = DataFrame(list_res2)['id'].tolist()
        assert path_id in path_ids
        # 更新课程路径
        pathNameNew = 'dibo_test_curriculum_path_new' + self.now
        pl = {
            "id": path_id,
            "pathName": pathNameNew,
            "regionPolicy": "JP",
            "status": 0
        }
        update_res = self.admin_curriculum.update_curriculum_path(self.admin_auth, **pl)
        assert update_res['data']['id'] == path_id
        assert update_res['data']['pathName'] == pathNameNew
        assert update_res['data']['regionPolicy'] == "JP"
        assert update_res['data']['status'] == 0
        # 更新课程路径后，查询路径列表，验证更新成功
        list_res3 = self.admin_curriculum.curriculum_path_list(self.admin_auth)['data']
        for item in list_res3:
            if item['id'] == path_id:
                assert item['pathName'] == pathNameNew
                assert item['regionPolicy'] == "JP"
                assert item['status'] == 0
                break
        else:
            assert False
        # 删除课程路径
        delete_res = self.admin_curriculum.delete_curriculum_path(self.admin_auth, path_id)
        assert delete_res['message'] == 'success'
        # 删除课程路径后，查询路径列表，验证删除成功
        list_res4 = self.admin_curriculum.curriculum_path_list(self.admin_auth)['data']
        if list_res4:
            path_ids = DataFrame(list_res4)['id'].tolist()
            assert path_id not in path_ids


    @pytest.mark.release
    def test_admin_curriculum_positive_curriculum_level(self, create_curriculum_path_fixtures):
        """课程路径 - 增删改查校验"""

        path_id = create_curriculum_path_fixtures
        # 创建课程等级
        goalTitle = "dibo_test_curriculum_goal" + self.now
        pl = {
            "levelNum": 2,
            "levelName": "Level 2",
            "goalTitle": goalTitle,
            "goalContent": ""
        }
        create_res = self.admin_curriculum.create_curriculum_level(self.admin_auth, path_id, **pl)
        level_id = create_res['data']['id']
        # 创建课程等级后，查询路径列表，验证新增成功
        list_res2 = self.admin_curriculum.curriculum_level_list(self.admin_auth, path_id)['data']
        level_ids = DataFrame(list_res2)['id'].tolist()
        assert level_id in level_ids
        # 更新课程等级
        goalTitleNew = 'dibo_test_curriculum_goal_new' + self.now
        pl = {
            "levelName": "Level 1",
            "goalTitle": goalTitleNew,
            "goalContent": ""
        }
        update_res = self.admin_curriculum.update_curriculum_level(self.admin_auth, level_id, **pl)
        assert update_res['data']['id'] == level_id
        assert update_res['data']['levelName'] == "Level 1"
        assert update_res['data']['goalTitle'] == goalTitleNew
        assert update_res['data']['goalContent'] == ""
        # 更新课程等级后，查询路径列表，验证更新成功
        list_res3 = self.admin_curriculum.curriculum_level_list(self.admin_auth, path_id)['data']
        for item in list_res3:
            if item['id'] == level_id:
                assert item['goalTitle'] == goalTitleNew
                assert item['levelName'] == "Level 1"
                assert item['goalContent'] == ""
                break
        else:
            assert False
        # 删除课程等级
        delete_res = self.admin_curriculum.delete_curriculum_level(self.admin_auth, level_id)
        assert delete_res['message'] == 'success'
        # 删除课程等级后，查询路径列表，验证删除成功
        list_res4 = self.admin_curriculum.curriculum_level_list(self.admin_auth, path_id)['data']
        if list_res4:
            level_ids = DataFrame(list_res4)['id'].tolist()
            assert level_id not in level_ids

    @pytest.mark.release
    def test_admin_curriculum_positive_create_ok(self):
        """创建课程单元-正向用例"""
        res = self.admin_curriculum.create(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_curriculum_permission_create(self, desc, value):
        """创建课程单元-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_curriculum.create(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_admin_curriculum_required_create_req(self, desc, value, code):
        """创建课程单元-必填字段测试(req)"""
        if desc == 'missing':
            pl = {'pop_items': 'req'}
        else:
            pl = {'req': value}
        res = self.admin_curriculum.create(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        else:
            assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
            assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
            assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('integer', 123, 200, 500),
            ('float', 12.3, 200, 500),
            ('boolean', True, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('email_format', 'test@example.com', 200, 500),
            ('phone_format', '13800138000', 200, 500),
            ('date_format', '2023-12-25', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 200, 500),
            ('unicode', 'chinese_test', 200, 500),
            ('json_string', '{"key": "value"}', 200, 500),
            ('xml_string', '<root><item>test</item></root>', 200, 500),
            ('url_string', 'https://www.example.com', 200, 500),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 500),
        ]
    )
    def test_admin_curriculum_format_create_req(self, desc, value, code, code_res):
        """创建课程单元-数据格式测试(req)"""
        try:
            res = self.admin_curriculum.create(self.authorization, req=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min_length', "", 500),
            ('max_length', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 500),
        ]
    )
    def test_admin_curriculum_boundary_create_req(self, desc, value, code):
        """创建课程单元-边界值测试(req)"""
        res = self.admin_curriculum.create(self.authorization, req=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_curriculum_scenario_create_invalid_req(self):
        """创建课程单元-场景异常-无效的req"""
        req = 'INVALID_VALUE'
        res = self.admin_curriculum.create(self.authorization, req=req)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('sql_injection', "' OR '1'='1", 403, ''),
            ('xss_script', "<script>alert('XSS')</script>", 403, ''),
            ('xss_img', "<img src=x onerror=alert('XSS')>", 403, ''),
            ('xss_iframe', "<iframe src=javascript:alert('XSS')></iframe>", 403, ''),
            ('xml_injection', "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", 403, ''),
            ('unicode_attack', '\\x00\\x01\\x02', 200, 404),
            ('crlf_injection', 'test%0d%0aSet-Cookie: admin=true', 200, 404),
            ('code_injection', "eval('alert(1)')", 403, ''),
            ('regex_dos', '((a+)+)+$', 403, ''),
        ]
    )
    def test_admin_curriculum_security_create_req(self, desc, value, code, code_res):
        """创建课程单元-安全测试(req)"""
        res = self.admin_curriculum.create(self.authorization, req=value)
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
        else:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == code_res, f"接口返回状态码异常: 预期【{code_res}】，实际【{res['code']}】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【'not found'】，实际【{res['message']}】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【'not found'】，实际【{res['data']}】"



    @pytest.mark.release
    def test_admin_curriculum_positive_getList_ok(self):
        """获取等级下Unit列表-正向用例"""
        res = self.admin_curriculum.getList(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_curriculum_permission_getList(self, desc, value):
        """获取等级下Unit列表-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_curriculum.getList(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_admin_curriculum_required_getList_levelId(self, desc, value, code):
        """获取等级下Unit列表-必填字段测试(levelId)"""
        if desc == 'missing':
            pl = {'pop_items': 'levelId'}
        else:
            pl = {'levelId': value}
        res = self.admin_curriculum.getList(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        else:
            assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
            assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
            assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 200, 500),
            ('float', 12.34, 200, 500),
            ('boolean', True, 200, 500),
            ('negative', -123, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
        ]
    )
    def test_admin_curriculum_format_getList_levelId(self, desc, value, code, code_res):
        """获取等级下Unit列表-数据格式测试(levelId)"""
        try:
            res = self.admin_curriculum.getList(self.authorization, levelId=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 200),
            ('zero', 0, 200),
            ('max', 2147483647, 200),
        ]
    )
    def test_admin_curriculum_boundary_getList_levelId(self, desc, value, code):
        """获取等级下Unit列表-边界值测试(levelId)"""
        res = self.admin_curriculum.getList(self.authorization, levelId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_curriculum_scenario_getList_invalid_levelId(self):
        """获取等级下Unit列表-场景异常-无效的levelId"""
        levelId = 999999999
        res = self.admin_curriculum.getList(self.authorization, levelId=levelId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"



    @pytest.mark.release
    def test_admin_curriculum_positive_update_ok(self):
        """更新课程单元-正向用例"""
        res = self.admin_curriculum.update(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_curriculum_permission_update(self, desc, value):
        """更新课程单元-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_curriculum.update(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_admin_curriculum_required_update_req(self, desc, value, code):
        """更新课程单元-必填字段测试(req)"""
        if desc == 'missing':
            pl = {'pop_items': 'req'}
        else:
            pl = {'req': value}
        res = self.admin_curriculum.update(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        else:
            assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
            assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
            assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('integer', 123, 200, 500),
            ('float', 12.3, 200, 500),
            ('boolean', True, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('email_format', 'test@example.com', 200, 500),
            ('phone_format', '13800138000', 200, 500),
            ('date_format', '2023-12-25', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 200, 500),
            ('unicode', 'chinese_test', 200, 500),
            ('json_string', '{"key": "value"}', 200, 500),
            ('xml_string', '<root><item>test</item></root>', 200, 500),
            ('url_string', 'https://www.example.com', 200, 500),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 500),
        ]
    )
    def test_admin_curriculum_format_update_req(self, desc, value, code, code_res):
        """更新课程单元-数据格式测试(req)"""
        try:
            res = self.admin_curriculum.update(self.authorization, req=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min_length', "", 500),
            ('max_length', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 500),
        ]
    )
    def test_admin_curriculum_boundary_update_req(self, desc, value, code):
        """更新课程单元-边界值测试(req)"""
        res = self.admin_curriculum.update(self.authorization, req=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_curriculum_scenario_update_invalid_req(self):
        """更新课程单元-场景异常-无效的req"""
        req = 'INVALID_VALUE'
        res = self.admin_curriculum.update(self.authorization, req=req)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('sql_injection', "' OR '1'='1", 403, ''),
            ('xss_script', "<script>alert('XSS')</script>", 403, ''),
            ('xss_img', "<img src=x onerror=alert('XSS')>", 403, ''),
            ('xss_iframe', "<iframe src=javascript:alert('XSS')></iframe>", 403, ''),
            ('xml_injection', "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", 403, ''),
            ('unicode_attack', '\\x00\\x01\\x02', 200, 404),
            ('crlf_injection', 'test%0d%0aSet-Cookie: admin=true', 200, 404),
            ('code_injection', "eval('alert(1)')", 403, ''),
            ('regex_dos', '((a+)+)+$', 403, ''),
        ]
    )
    def test_admin_curriculum_security_update_req(self, desc, value, code, code_res):
        """更新课程单元-安全测试(req)"""
        res = self.admin_curriculum.update(self.authorization, req=value)
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
        else:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == code_res, f"接口返回状态码异常: 预期【{code_res}】，实际【{res['code']}】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【'not found'】，实际【{res['message']}】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【'not found'】，实际【{res['data']}】"



    @pytest.mark.release
    def test_admin_curriculum_positive_unit_details_ok(self):
        """删除课程单元-正向用例"""
        res = self.admin_curriculum.unit_details(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_admin_curriculum_permission_unit_details(self, desc, value):
        """删除课程单元-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_curriculum.unit_details(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 200, 500),
            ('float', 12.34, 200, 500),
            ('boolean', True, 200, 500),
            ('negative', -123, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
        ]
    )
    def test_admin_curriculum_format_unit_details_id(self, desc, value, code, code_res):
        """删除课程单元-数据格式测试(id)"""
        try:
            res = self.admin_curriculum.unit_details(self.authorization, id=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 200),
            ('zero', 0, 200),
            ('max', 2147483647, 200),
        ]
    )
    def test_admin_curriculum_boundary_unit_details_id(self, desc, value, code):
        """删除课程单元-边界值测试(id)"""
        res = self.admin_curriculum.unit_details(self.authorization, id=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_curriculum_scenario_unit_details_invalid_id(self):
        """删除课程单元-场景异常-无效的id"""
        id = 999999999
        res = self.admin_curriculum.unit_details(self.authorization, id=id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

