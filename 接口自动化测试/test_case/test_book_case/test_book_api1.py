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
        # 查询故事书标签类型列表
        self.bookTagtType_id = self.book.bookTagTypeList(self.authorization)['data']['content'][0]['id']

    @pytest.fixture(scope="class")
    def get_bookId(self):
        '''方法前置 - 获取bookid'''
        bookList = self.book.book_list(self.authorization)
        yield bookList

    @pytest.fixture(scope='function')
    def create_BookTagType(self):
        description = '创建书籍标签类型描述'
        name = 'createBookTagType' + self.now
        res = self.book.createBookTagType(self.authorization, description=description, name=name)
        bookTagTypeId = res['data']['id']

        yield bookTagTypeId

        res = self.book.deleteBookTagType(self.authorization, bookTagTypeId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'

    @pytest.fixture(scope='function')
    def create_BookTag(self, create_BookTagType, get_bookId):
        '''创建故事书标签'''
        tagDescription = '创建书籍标签描述'
        tagName = 'createBookTag' + self.now
        tagTypeId = create_BookTagType
        bookTagId = self.book.createBookTag(self.authorization, tagDescription, tagName, tagTypeId)['data']['id']
        bookId = get_bookId["data"]["content"][0]["id"]
        self.book.addTagToBook(self.authorization, bookId, bookTagId)
        yield bookId, bookTagId
        res = self.book.deleteBookTag(self.authorization, bookTagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"

    @pytest.mark.release
    def test_book_positive_removeTagFromBook_ok(self, create_BookTag):
        """删除故事书与标签的关联关系-正向用例"""
        bookId, bookTagId = create_BookTag
        res = self.book.removeTagFromBook(self.authorization, bookId=bookId, tagId=bookTagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == '删除成功', f"接口返回data数据异常：{res['data']}"

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
            ('empty', "", 400),
            ('null', None, 500),
        ]
    )
    def test_book_required_removeTagFromBook_bookId(self, desc, value, code, create_BookTag):
        """删除故事书与标签的关联关系-必填字段测试(bookId)"""
        if desc == 'missing':
            pl = {'pop_items': 'bookId'}
        else:
            pl = {'bookId': value}
        bookId, bookTagId = create_BookTag
        res = self.book.removeTagFromBook(self.authorization, tagId=bookTagId, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【pending】，实际【{res['data']}】"
        else:
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【100006】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【pending】，实际【{res['data']}]"

    @pytest.mark.release
    def test_book_scenario_removeTagFromBook_invalid_bookId(self, create_BookTag):
        """删除故事书与标签的关联关系-场景异常-无效的bookId"""
        bookId, bookTagId = create_BookTag
        bookId = 100
        res = self.book.removeTagFromBook(self.authorization, bookId=bookId, tagId=bookTagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100054, f"接口返回状态码异常: 预期【100054】，实际【{res['code']}】"
        assert res['message'] == 'Resource not found', f"接口返回message信息异常: 预期【Resource not found】，实际【{res['message']}】"
        assert res['data'] == 'Resource not found', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 400),
            ('null', None, 500),
        ]
    )
    def test_book_required_removeTagFromBook_tagId(self, desc, value, code, create_BookTag):
        """删除故事书与标签的关联关系-必填字段测试(tagId)"""
        if desc == 'missing':
            pl = {'pop_items': 'tagId'}
        else:
            pl = {'tagId': value}
        bookId, bookTagId = create_BookTag
        res = self.book.removeTagFromBook(self.authorization, bookId=bookId, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【pending】，实际【{res['data']}】"
        else:
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【100006】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【pending】，实际【{res['data']}]"

    @pytest.mark.release
    def test_book_scenario_removeTagFromBook_invalid_tagId(self, create_BookTag):
        """删除故事书与标签的关联关系-场景异常-无效的tagId"""
        bookId, bookTagId = create_BookTag
        bookTagId = 100
        res = self.book.removeTagFromBook(self.authorization, bookId=bookId, tagId=bookTagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100054, f"接口返回状态码异常: 预期【100054】，实际【{res['code']}】"
        assert res['message'] == 'Resource not found', f"接口返回message信息异常: 预期【Resource not found】，实际【{res['message']}】"
        assert res['data'] == 'Resource not found', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_book_positive_bookTagRelationList_ok(self, create_BookTag):
        """查询故事书标签关联列表-正向用例"""
        bookId, bookTagId = create_BookTag
        res = self.book.bookTagRelationList(self.authorization, bookId=bookId, tagId=bookTagId)
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

    @pytest.fixture(scope='function')
    def create_BookTagType(self):
        '''创建多个故事书标签'''
        tagIds = []
        for i in range(3):
            tagDescription = '创建书籍标签描述'
            tagName = 'createBookTag' + self.now + str(i)
            id = self.book.createBookTag(self.authorization, tagDescription, tagName, self.bookTagtType_id)['data']['id']
            tagIds.append(id)
        yield tagIds
        for bookTagId in tagIds:
            res = self.book.deleteBookTag(self.authorization, bookTagId)
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'

    @pytest.mark.release
    def test_book_positive_batchUpdateBookTags_ok(self, get_bookId, create_BookTagType):
        """批量更新故事书的标签-正向用例"""
        bookId = get_bookId["data"]["content"][0]["id"]
        tagIds = create_BookTagType
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
            ('empty', [], 400),
            ('null', None, 500),
        ]
    )
    def test_book_required_batchUpdateBookTags_tagIds(self, desc, value, code, get_bookId):
        """批量更新故事书的标签-必填字段测试(tagIds)"""
        bookId = get_bookId["data"]["content"][0]["id"]
        if desc == 'missing':
            pl = {'pop_items': 'tagIds'}
        else:
            pl = {'tagIds': value}
        res = self.book.batchUpdateBookTags(self.authorization, bookId, code=code, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【pending】，实际【{res['data']}】"
        else:
            assert res['code'] == 200, f"接口返回状态码异常: 预期【pending】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'] == '批量更新成功', f"接口返回data数据异常：预期【批量更新成功】，实际【{res['data']}】"

    @pytest.mark.release
    def test_book_positive_autoGenerateBookTags_ok(self, get_bookId):
        """自动生成并保存故事书标签-正向用例"""
        bookId = get_bookId["data"]["content"][0]["id"]
        res = self.book.autoGenerateBookTags(self.authorization, bookId=bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == '标签生成任务已启动', f"接口返回data数据异常：预期【标签生成任务已启动】，实际【{res['data']}】"

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
    def test_book_permission_autoGenerateBookTags(self, desc, value):
        """自动生成并保存故事书标签-权限测试"""
        bookId = 1999999    # todo
        res = self.book.autoGenerateBookTags(self.authorization, bookId=bookId, code=200)
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == '标签生成任务已启动', f"接口返回data数据异常：预期【标签生成任务已启动】，实际【{res['data']}】"

    @pytest.mark.release
    def test_book_positive_triggerTagBasedRecommendation_ok(self):
        """手动触发基于标签的故事书推荐计算-正常流程测试"""
        res = self.book.triggerTagBasedRecommendation(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == '推荐计算任务已完成', f"接口返回data数据异常：{res['data']}"

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
    def test_book_permission_triggerTagBasedRecommendation(self, desc, value):
        """手动触发基于标签的故事书推荐计算-权限测试"""
        res = self.book.triggerTagBasedRecommendation(authorization=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == '推荐计算任务已完成', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_recommend_positive_storybookRecommend_ok(self, get_bookId):
        """获取故事书推荐-正常流程测试"""
        readBookIds = get_bookId
        pl = {
            "readBookIds": [1, 2, 3],
            "recommendCount": 5,
            "recommendationFocus": "similar"
        }
        res = self.book.triggerTagBasedRecommendation(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == '推荐计算任务已完成', f"接口返回data数据异常：{res['data']}"

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
    def test_recommend_permission_storybookRecommend(self, desc, value):
        """获取故事书推荐-权限测试"""
        res = self.book.triggerTagBasedRecommendation(authorization=value)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"
