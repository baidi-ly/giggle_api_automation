from time import strftime

import pytest
import sys
import os

from test_case.page_api.admin.admin_cast_api import AdminCastApi
from test_case.page_api.cast.cast_api import CastApi

sys.path.append(os.getcwd())
sys.path.append("..")


@pytest.mark.Course
class TestCourse:

    def setup_class(self):
        self.cast = CastApi()
        self.admin_cast = AdminCastApi()
        self.authorization = self.cast.get_authorization()[0]
        self.admin_auth = self.admin_cast.get_admin_authorization()[0]

        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.smoke
    @pytest.mark.parametrize('languageCode',
         ["en", "zh", "zh-Hant", "es", "fr", "de", "ja",
          "ko", "ru","pt", "pt-BR", "ar", "hi","id", "vi", "tr","bn",
          "nl","it", "th", "pl", "uk", "fil",  "ms", "sw",  "ur",
         ])
    def test_cast_positive_getAlbums_ok(self, languageCode):
        """查询播客的专辑-多语言验证"""
        res = self.cast.getAlbums(self.authorization, languageCode)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        for album in res['data']:
            if languageCode == "en":
                assert album['localName' ] in ['Alphabet Songs', 'Learning Journey Songs']
            elif languageCode == "zh":
                assert album['localName' ] in ['字母歌', '学习之旅歌曲']
            elif languageCode == "zh-Hant":
                assert album['localName' ] in ['字母歌曲', '學習之旅歌曲']
            elif languageCode == "es":
                assert album['localName' ] in ['Canciones del alfabeto', 'Canciones de aprendizaje']
            elif languageCode == "de":
                assert album['localName' ] in ['Alphabet-Lieder', 'Lieder der Lernreise']
            elif languageCode == "ja":
                assert album['localName' ] in ['学習の旅の歌', 'アルファベットの歌']
            elif languageCode == "ko":
                assert album['localName' ] in ['알파벳 노래', '학습 여정 노래']
            elif languageCode == "ru":
                assert album['localName' ] in ['Песни алфавита', 'Песни для обучения']
            elif languageCode == "pt":
                assert album['localName' ] in ['Músicas Alfabeto', 'Músicas de Aprendizagem']
            elif languageCode == "pt-BR":
                assert album['localName' ] in ['Músicas do Alfabeto', 'Músicas da Jornada de Aprendizado']
            elif languageCode == "ar":
                assert album['localName' ] in ['أغاني الأبجدية', 'أغاني رحلة التعلم']
            elif languageCode == "hi":
                assert album['localName' ] in ['वर्णमाला गीत', 'सीखने की यात्रा के गीत']
            elif languageCode == "id":
                assert album['localName' ] in ['Lagu Abjad', 'Lagu Perjalanan Belajar']
            elif languageCode == "vi":
                assert album['localName' ] in ['Bài hát vần chữ', 'Bài hát hành trình học tập']
            elif languageCode == "tr":
                assert album['localName' ] in ['Alfabe Şarkıları', 'Öğrenme Şarkıları']
            elif languageCode == "bn":
                assert album['localName' ] in ['বর্ণমালার গান', 'শিক্ষার যাত্রা গান']
            elif languageCode == "nl":
                assert album['localName' ] in ['Alfabetliedjes', 'Leerliedjes']
            elif languageCode == "th":
                assert album['localName' ] in ['เพลงตัวอักษร', 'เพลงแห่งการเรียนรู้']
            elif languageCode == "pl":
                assert album['localName' ] in ['Piosenki o nauce podróży', 'Piosenki alfabetowe']
            elif languageCode == "uk":
                assert album['localName' ] in ['Пісні абетки', 'Пісні для навчання']
            elif languageCode == "fil":
                assert album['localName' ] in ['Mga Kanta ng Alpabeto', 'Mga Kanta sa Learning Journey']
            elif languageCode == "ms":
                assert album['localName' ] in ['Lagu Abjad', 'Lagu Jejak Pembelajaran']
            elif languageCode == "sw":
                assert album['localName' ] in ['Nyimbo za Alfabeti', 'Nyimbo za Safari ya Kujifunza']
            elif languageCode == "ur":
                assert album['localName' ] in ['حروف تہجی گانے', 'سیکھنے کے سفر کے گانے']
            assert album['name' ] in ['Alphabet Songs', 'Learning Journey Songs']

    @pytest.mark.smoke
    def test_cast_positive_getAlbums_withoutLocalName_ok(self):
        """查询播客的专辑-正向用例"""
        res = self.cast.getAlbums(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        for content in res['data']:
            assert 'localName' not in content, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_cast_permission_getAlbums(self, desc, value):
        """查询播客的专辑-权限测试"""
        res = self.cast.getAlbums(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        for content in res['data']:
            assert 'localName' not in content, f"接口返回data数据异常：{res['data']}"
