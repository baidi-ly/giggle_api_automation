import datetime
from time import strftime

import pytest
import sys
import os

from test_case.page_api.book.book_api import BookApi

sys.path.append(os.getcwd())

from test_case.page_api.verify.verify_api import VerifyApi


@pytest.mark.verify
class TestVerifyApiGenerated:
    def setup_class(self):
        self.vertify = VerifyApi()
        self.book = BookApi()
        self.authorization = self.vertify.get_authorization()[0]
        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.fixture(scope='function')
    def create_book(self):
        category = self.book.getBookCategories(self.authorization)['data'][0]['id']
        bookName = "debbie_test_book" + self.now
        description = "debbie_test_book_description" + self.now
        pl = {
            "category": category,
            "maxAge": 0,
            "minAge": 12,
            "seriesId": 0,
            "storyType": 'Fiction'
        }
        file = {
            'file': ('story_face.webp', open(os.getcwd() + '/test_data/story_face.webp', 'rb'))
        }
        bookId = self.book.createormodifybook(self.authorization, description=description,
                                                  bookName=bookName, file=file, **pl)['data']['id']
        yield bookId

        self.book.delete_book(self.authorization, bookId)

    def test_noargs_getAuditors_basic(self):
        """获取所有审核员"""
        res = self.vertify.getAuditors(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    @pytest.mark.parametrize('joinCompetition', [True, False])
    def test_verify_positive_submittopublic_ok(self, create_book, joinCompetition):
        """提交public审核-正向用例"""
        bookId = create_book
        book_status_before = self.book.book_details(self.authorization, bookId)['data']['status']
        assert book_status_before == 0, "新建故事书状态不为私有（仅自己可见）！"
        res = self.vertify.submittopublic(self.authorization, bookId, joinCompetition)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
        assert res['data']['status'] == 2, "自动审核失败！"
        book_status_after = self.book.book_details(self.authorization, bookId)['data']['status']
        assert book_status_after == 2, "自动审核后，故事书状态不为待审核！"

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
    def test_book_permission_submittopublic(self, desc, value):
        """删除故事书与标签的关联关系-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.book.removeTagFromBook(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize('joinCompetition', [10, 'string_test'])
    def test_verify_positive_submittopublic_abnormal(self, create_book, joinCompetition):
        """提交public审核-不正确的joinCompetition格式"""
        bookId = create_book
        res = self.vertify.submittopublic(self.authorization, bookId, joinCompetition, code=400)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100006, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
        assert res['data'] == f"Failed to convert value of type 'java.lang.String' to required type 'java.lang.Boolean'; nested exception is java.lang.IllegalArgumentException: Invalid boolean value [{joinCompetition}]", f"接口返回data数据异常：{res['data']}"