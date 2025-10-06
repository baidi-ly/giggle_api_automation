import datetime

import pytest
import sys
import os

from test_case.page_api.course.course_api import CourseApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.learning.learning_api import LearningApi
from test_case.page_api.materials.materials_api import MaterialsApi

sys.path.append(os.getcwd())
sys.path.append("..")


@pytest.mark.material
class TestMaterial:

    def setup_class(self):
        self.materials = MaterialsApi()
        self.authorization = self.materials.get_authorization()

    @pytest.mark.release
    def test_materials_upload_common_resource_ppt(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        file = {
            'file': ('upload_test.txt', open(os.getcwd() + '/test_data/upload_test.txt', 'rb'))
        }
        stats_res = self.materials.upload_common_resource(self.authorization, file)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["message"] == "文件上传成功"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('empty_file', 'test_files/empty.txt'),
            ('small_file', 'test_files/small.txt'),
            ('large_file', 'test_files/large.txt'),
            ('invalid_format', 'test_files/invalid.exe'),
            ('max_size', 'test_files/max_size.txt'),
        ]
    )
    def test_materials_boundary_uploadCommonResource_file(self, desc, value):
        """uploadCommonResource-边界值测试(file)"""
        file = {
            'file': (value, open(os.getcwd() + f'/test_data/{value}', 'rb'))
        }
        res = self.materials.uploadCommonResource(self.authorization, file=file)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"