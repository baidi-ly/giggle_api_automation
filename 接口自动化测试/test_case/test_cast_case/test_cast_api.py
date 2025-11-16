
import pytest
import sys
import os

from test_case.page_api.cast.cast_api import CastApi

sys.path.append(os.getcwd())
sys.path.append("..")


@pytest.mark.Course
class TestCourse:

    def setup_class(self):
        self.cast = CastApi()
        self.authorization = self.cast.get_authorization()[0]

    @pytest.mark.release
    @pytest.mark.parametrize('languageCode',
         ["en", "zh", "zh-Hant", "es", "fr", "de", "ja",
          "ko", "ru","pt", "pt-BR", "ar", "hi","id", "vi", "tr","bn",
          "nl","it", "th", "pl", "uk", "fil",  "ms", "sw",  "ur",
         ])
    def test_cast_positive_getAlbums_ok(self, languageCode):
        """查询播客的专辑-正向用例"""
        res = self.cast.getAlbums(self.authorization, languageCode)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        for content in res['data']:
            assert 'localName' in content, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_cast_positive_getAlbums_withoutLocalName_ok(self):
        """查询播客的专辑-正向用例"""
        res = self.cast.getAlbums(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        for content in res['data']:
            assert 'localName' not in content, f"接口返回data数据异常：{res['data']}"

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
    def test_cast_permission_getAlbums(self, desc, value):
        """查询播客的专辑-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.cast.getAlbums(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        for content in res['data']:
            assert 'localName' not in content, f"接口返回data数据异常：{res['data']}"
