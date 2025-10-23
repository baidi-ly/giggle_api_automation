import datetime
import sys
import os
from time import strftime

from test_case.page_api.book.book_api import BookApi
from test_case.page_api.kid.kid_api import KidApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.book
class TestBook:

    def setup_class(self):
        self.book = BookApi()
        self.kid = KidApi()
        self.authorization, self.userId = self.book.get_authorization()
        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.release
    def test_book_positive_removeTagFromBook_ok(self):
        """删除故事书与标签的关联关系-正向用例"""
        res = self.book.removeTagFromBook(self.authorization)
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
    def test_book_permission_removeTagFromBook(self, desc, value):
        """删除故事书与标签的关联关系-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.book.removeTagFromBook(value, code=401)
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
    def test_book_required_removeTagFromBook_bookId(self, desc, value, code):
        """删除故事书与标签的关联关系-必填字段测试(bookId)"""
        if desc == 'missing':
            pl = {'pop_items': 'bookId'}
        else:
            pl = {'bookId': value}
        res = self.book.removeTagFromBook(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【pending】，实际【{res['data']}】"
        else:
            assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【pending】，实际【{res['code']}】"
            assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【pending】，实际【{res['message']}】"
            assert res['data'] == '${pending}', f"接口返回data数据异常：预期【pending】，实际【{res['data']}】"

    @pytest.mark.release
    def test_book_scenario_removeTagFromBook_invalid_bookId(self):
        """删除故事书与标签的关联关系-场景异常-无效的bookId"""
        bookId = 'INVALID_VALUE'
        res = self.book.removeTagFromBook(self.authorization, bookId=bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
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
    def test_book_required_removeTagFromBook_tagId(self, desc, value, code):
        """删除故事书与标签的关联关系-必填字段测试(tagId)"""
        if desc == 'missing':
            pl = {'pop_items': 'tagId'}
        else:
            pl = {'tagId': value}
        res = self.book.removeTagFromBook(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【pending】，实际【{res['data']}】"
        else:
            assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【pending】，实际【{res['code']}】"
            assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【pending】，实际【{res['message']}】"
            assert res['data'] == '${pending}', f"接口返回data数据异常：预期【pending】，实际【{res['data']}】"

    @pytest.mark.release
    def test_book_scenario_removeTagFromBook_invalid_tagId(self):
        """删除故事书与标签的关联关系-场景异常-无效的tagId"""
        tagId = 'INVALID_VALUE'
        res = self.book.removeTagFromBook(self.authorization, tagId=tagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_book_positive_bookTagRelationList_ok(self):
        """查询故事书标签关联列表-正向用例"""
        res = self.book.bookTagRelationList(self.authorization)
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
    def test_book_permission_bookTagRelationList(self, desc, value):
        """查询故事书标签关联列表-权限测试"""
        res = self.book.bookTagRelationList(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_book_positive_batchUpdateBookTags_ok(self):
        """批量更新故事书的标签-正向用例"""
        bookId = 1
        tagIds = [1, 2, 3]
        res = self.book.batchUpdateBookTags(self.authorization, bookId, tagIds)
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
    def test_book_permission_batchUpdateBookTags(self, desc, value):
        """批量更新故事书的标签-权限测试"""
        bookId = 1
        tagIds = [1, 2, 3]
        res = self.book.batchUpdateBookTags(value, bookId, tagIds, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing', 'missing', 500),
            ('empty', [], 500),
            ('null', None, 500),
        ]
    )
    def test_book_required_batchUpdateBookTags_tagIds(self, desc, value, code):
        """批量更新故事书的标签-必填字段测试(tagIds)"""
        bookId = 1
        if desc == 'missing':
            pl = {'pop_items': 'tagIds'}
        else:
            pl = {'tagIds': value}
        res = self.book.batchUpdateBookTags(authorization=self.authorization, bookId=bookId, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【pending】，实际【{res['data']}】"
        else:
            assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【pending】，实际【{res['code']}】"
            assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【pending】，实际【{res['message']}】"
            assert res['data'] == '${pending}', f"接口返回data数据异常：预期【pending】，实际【{res['data']}】"

    @pytest.mark.release
    def test_book_positive_autoGenerateBookTags_ok(self):
        """自动生成并保存故事书标签-正向用例"""
        bookId = 1
        res = self.book.autoGenerateBookTags(self.authorization, bookId=bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：预期【pending】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, authorization, code',
        [
            ('no_auth', '', 401),
            ('empty_token', ' ', 401),
            ('expired_token', 'expired_token_123', 401),
            ('invalid_token', 'invalid_token_456', 401),
        ]
    )
    def test_book_permission_autoGenerateBookTags(self, desc, authorization, code):
        """自动生成并保存故事书标签-权限测试"""
        bookId = 1
        res = self.book.autoGenerateBookTags(authorization=authorization, bookId=bookId, code=code)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_book_positive_triggerTagBasedRecommendation_ok(self):
        """手动触发基于标签的故事书推荐计算-正常流程测试"""
        res = self.book.triggerTagBasedRecommendation(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, authorization, code',
        [
            ('missing_auth', '', 401),
            ('empty_auth', '', 401),
            ('null_auth', None, 401),
            ('invalid_auth', 'invalid_token', 401),
            ('expired_auth', 'expired_token_12345', 401),
        ]
    )
    def test_book_permission_triggerTagBasedRecommendation(self, desc, authorization, code):
        """手动触发基于标签的故事书推荐计算-权限测试"""
        res = self.book.triggerTagBasedRecommendation(authorization=authorization, code=code)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"