
import sys
import os

from test_case.page_api.admin.admin_cast_api import AdminCastApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.AdminUser
class TestAdminUser:

    def setup_class(self):
        self.admin_cast = AdminCastApi()
        self.authorization = self.admin_cast.get_admin_authorization()

    @pytest.mark.release
    @pytest.mark.parametrize('languageCode',
         ["en", "zh", "zh-Hant", "es", "fr", "de", "ja",
          "ko", "ru","pt", "pt-BR", "ar", "hi","id", "vi", "tr","bn",
          "my", "nl","it", "th", "pl", "ro",  "uk", "fil",  "ms", "sw",  "ur",
         ])
    def test_admin_cast_positive_getAlbums_ok(self, languageCode):
        """查询播客的专辑-正向用例"""
        res = self.admin_cast.getAlbums(self.authorization, languageCode)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        for content in res['data']:
            assert 'localName' in content, f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_admin_cast_positive_getAlbums_withoutLocalName_ok(self):
        """查询播客的专辑-正向用例"""
        res = self.admin_cast.getAlbums(self.authorization)
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
    def test_admin_cast_permission_getAlbums(self, desc, value):
        """查询播客的专辑-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.admin_cast.getAlbums(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
