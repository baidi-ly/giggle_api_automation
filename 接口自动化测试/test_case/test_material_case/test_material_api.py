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


@pytest.mark.Course
class TestCourse:

    def setup_class(self):
        self.materials = MaterialsApi()
        self.authorization = self.materials.get_authorization()

    @pytest.mark.pendingRelease
    def test_materials_upload_common_resource_ppt(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        files = {
            'file1': ('file1.txt', open('file1.txt', 'rb'))
        }
        stats_res = self.materials.upload_common_resource(self.authorization, files)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["learningStats"]

    @pytest.mark.pendingRelease
    @pytest.mark.parametrize("format", ["txt", "md", "doc", "docx", "xls", "xlsx", "ppt"], ids=["intger", "boolen", "special characters"])
    def test_materials_upload_common_resource_file(self, format):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        files = {
            'file1': (f'file1.{format}', open('file1.txt', 'rb'))
        }
        stats_res = self.materials.upload_common_resource(self.authorization, files)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["learningStats"]

    @pytest.mark.pendingRelease
    @pytest.mark.parametrize("format", ["jpg", "png", "gif", "bmp", "xls", "xlsx", "ppt"], ids=["intger", "boolen", "special characters"])
    def test_materials_upload_common_resource_image(self, format):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        files = {
            'file1': (f'file1.{format}', open('file1.txt', 'rb'))
        }
        stats_res = self.materials.upload_common_resource(self.authorization, files)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["learningStats"]

    @pytest.mark.pendingRelease
    @pytest.mark.parametrize("format", ["mp4", "avi", "mov"], ids=["mp4", "avi", "mov"])
    def test_materials_upload_common_resource_video(self, format):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        files = {
            'file1': (f'file1.{format}', open('file1.txt', 'rb'))
        }
        stats_res = self.materials.upload_common_resource(self.authorization, files)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["learningStats"]

    @pytest.mark.pendingRelease
    def test_materials_upload_common_resource_audio(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        files = {
            'file1': ('file1.mp3', open('file1.txt', 'rb'))
        }
        stats_res = self.materials.upload_common_resource(self.authorization, files)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["learningStats"]

    @pytest.mark.pendingRelease
    @pytest.mark.parametrize("format", ["zip", "rar", "tar"], ids=["zip", "rar", "tar"])
    def test_materials_upload_common_resource_zip(self, format):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        files = {
            'file1': (f'file1.{format}', open('file1.txt', 'rb'))
        }
        stats_res = self.materials.upload_common_resource(self.authorization, files)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["learningStats"]

    @pytest.mark.pendingRelease
    @pytest.mark.parametrize("format", ["exe", "apk", "bat"], ids=["exe", "apk", "bat"])
    def test_materials_upload_common_resource_executable(self, format):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        files = {
            'file1': ('file1.mp3', open('file1.txt', 'rb'))
        }
        stats_res = self.materials.upload_common_resource(self.authorization, files)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["learningStats"]

    @pytest.mark.pendingRelease
    def test_materials_upload_common_resource_multi(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        files = {
            'file1': ('file1.txt', open('file1.txt', 'rb')),
            'file2': ('file2.jpg', open('file2.jpg', 'rb')),
            'file3': ('file1.txt', open('file1.txt', 'rb')),
            'file4': ('file2.jpg', open('file2.jpg', 'rb'))
        }
        stats_res = self.materials.upload_common_resource(self.authorization, files)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["learningStats"]

    @pytest.mark.pendingRelease
    def test_materials_upload_common_resource_empty(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        stats_res = self.materials.upload_common_resource(self.authorization)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["learningStats"]

    @pytest.mark.pendingRelease
    def test_materials_upload_common_resource_unauthorized(self):
        """有效的kidId，返回完整统计数据"""
        # 获取有效的kidId
        # 获取孩子学习统计数据
        files = {
            'file1': ('file1.mp3', open('file1.txt', 'rb'))
        }
        stats_res = self.materials.upload_common_resource('', files)
        assert "data" in stats_res, f"获取孩子学习统计数据接口没有data数据，response->{stats_res}"
        assert stats_res["data"]["learningStats"]