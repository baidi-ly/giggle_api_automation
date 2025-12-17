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
        self.authorization = self.materials.get_authorization()[0]

    @pytest.mark.smoke
    def test_materials_upload_common_resource_jpeg(self):
        """上传公共资源"""
        # 上传公共资源
        file = {
            'file': ('flower.jpeg', open(os.getcwd() + '/test_data/flower.jpeg', 'rb'))
        }
        upload_res = self.materials.uploadCommonResource(self.authorization, 'jpeg', file)
        assert upload_res["data"]['contentType'] == 'jpeg'
        assert upload_res["data"]['fileSize'] == 133726
        assert upload_res["data"]['originalFilename'] == 'flower.jpeg'
        assert upload_res["data"]['message'] == '文件上传成功'