import datetime
from time import strftime

import pytest
import sys
import os

from test_case.page_api.materials.materials_api import MaterialsApi
from test_case.page_api.poster.poster_api import PosterApi

sys.path.append(os.getcwd())
sys.path.append("..")


@pytest.mark.Poster
class TestPoster:

    def setup_class(self):
        self.poster = PosterApi()
        self.materials = MaterialsApi()
        self.authorization = self.poster.get_authorization()[0]

        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.fixture(scope="class")
    def posterList(self):
        '''类前置 - 获取kidId'''
        posterList = self.poster.poster_list(self.authorization)
        yield posterList

    @pytest.mark.smoke
    def test_generate_poster_positive(self):
        """正向用例：使用有效的模板ID生成海报"""

        # 1. 先获取海报模板列表
        posters = self.poster.poster_list(self.authorization)['data']
        if not posters:
            assert False, "❌ 没有可用的海报模板，测试跳过"

        # 2. 选择第一个模板
        poster = posters[0]
        poster_id = str(poster.get('id'))

        # 3. 生成海报（使用URL类型）
        result = self.poster.generate_poster(self.authorization, poster_id)
        url = result['data']

        # 4. 下载海报
        fileName = '海报' + self.now
        self.materials.download_materials(self.authorization, '', fileName, fileType="png", url=url)

    @pytest.mark.smoke
    def test_generate_poster_base64(self):
        """正向用例：生成base64格式的海报"""

        # 1. 先获取海报模板列表
        posters = self.poster.poster_list(self.authorization)['data']
        if not posters:
            return False, "❌ 没有可用的海报模板，测试跳过"

        # 2. 选择第一个模板
        poster_id = str(posters[0].get('id'))

        # 3. 生成海报（使用URL类型）
        result = self.poster.generate_poster(self.authorization, poster_id,
                                             bind={"name": "Base64测试"}, poster_file_type="base64")
        url = result['data']

        # 4. 下载海报
        fileName = '海报' + self.now
        self.materials.download_materials(self.authorization, '', fileName, fileType="png", url=url)