
import pytest
import sys
import os

import config
from test_case.page_api.book.book_api import BookApi
from test_case.page_api.common.common_api import CommonApi

sys.path.append(os.getcwd())
sys.path.append("..")

expired_token = config.RunConfig.expired_token


@pytest.mark.common
class TestCommon:

    def setup_class(self):
        self.common = CommonApi()
        self.book = BookApi()
        self.authorization = self.common.get_authorization()[0]

    @pytest.mark.release
    def test_common_positive_getGetfileurl_ok(self):
        """根据url获取文件的下载链接-正向用例"""
        books_res = self.book.book_list(self.authorization)['data']['content']
        for book in books_res:
            if book['bookName'] == 'Little Ray':
                bookId = book['id']
                break
        key_url = self.book.coverDetailUrl(self.authorization, bookId)['data']['url']
        res = self.common.getGetfileurl(self.authorization, key_url)
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
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_common_permission_getGetfileurl(self, desc, value):
        """根据url获取文件的下载链接-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.common.getGetfileurl(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
