import datetime
import json
import sys
import os
from time import strftime

from pandas import DataFrame

import config
from test_case.page_api.base_api import BaseAPI
from test_case.page_api.book.book_api import BookApi
from test_case.page_api.kid.kid_api import KidApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

base_url = BaseAPI().baseurl()
expired_token = config.RunConfig.expired_token

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

    @pytest.mark.smoke
    def test_book_positive_removeTagFromBook_ok(self, create_BookTag):
        """删除故事书与标签的关联关系-正向用例"""
        bookId, bookTagId = create_BookTag
        res = self.book.removeTagFromBook(self.authorization, bookId=bookId, tagId=bookTagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == '删除成功', f"接口返回data数据异常：{res['data']}"

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

    def test_book_scenario_removeTagFromBook_invalid_bookId(self, create_BookTag):
        """删除故事书与标签的关联关系-场景异常-无效的bookId"""
        bookId, bookTagId = create_BookTag
        bookId = 100
        res = self.book.removeTagFromBook(self.authorization, bookId=bookId, tagId=bookTagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100054, f"接口返回状态码异常: 预期【100054】，实际【{res['code']}】"
        assert res['message'] == 'Resource not found', f"接口返回message信息异常: 预期【Resource not found】，实际【{res['message']}】"
        assert res['data'] == 'Resource not found', f"接口返回data数据异常：{res['data']}"

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

    def test_book_scenario_removeTagFromBook_invalid_tagId(self, create_BookTag):
        """删除故事书与标签的关联关系-场景异常-无效的tagId"""
        bookId, bookTagId = create_BookTag
        bookTagId = 100
        res = self.book.removeTagFromBook(self.authorization, bookId=bookId, tagId=bookTagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100054, f"接口返回状态码异常: 预期【100054】，实际【{res['code']}】"
        assert res['message'] == 'Resource not found', f"接口返回message信息异常: 预期【Resource not found】，实际【{res['message']}】"
        assert res['data'] == 'Resource not found', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_book_positive_bookTagRelationList_ok(self, create_BookTag):
        """查询故事书标签关联列表-正向用例"""
        bookId, bookTagId = create_BookTag
        res = self.book.bookTagRelationList(self.authorization, bookId=bookId, tagId=bookTagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

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
    def create_BookTagTypes(self):
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

    @pytest.mark.smoke
    def test_book_positive_batchUpdateBookTags_ok(self, get_bookId, create_BookTagTypes):
        """批量更新故事书的标签-正向用例"""
        bookId = get_bookId["data"]["content"][0]["id"]
        tagIds = create_BookTagTypes
        res = self.book.batchUpdateBookTags(self.authorization, bookId, tagIds)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

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

    @pytest.mark.smoke
    def test_book_positive_autoGenerateBookTags_ok(self, get_bookId):
        """自动生成并保存故事书标签-正向用例"""
        bookId = get_bookId["data"]["content"][0]["id"]
        res = self.book.autoGenerateBookTags(self.authorization, bookId=bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == '标签生成任务已启动', f"接口返回data数据异常：预期【标签生成任务已启动】，实际【{res['data']}】"

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

    @pytest.mark.smoke
    def test_book_positive_triggerTagBasedRecommendation_ok(self):
        """手动触发基于标签的故事书推荐计算-正常流程测试"""
        res = self.book.triggerTagBasedRecommendation(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == '推荐计算任务已完成', f"接口返回data数据异常：{res['data']}"

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

    @pytest.mark.smoke
    def test_recommend_positive_storybookRecommend_ok(self, get_bookId):
        """获取故事书推荐-正常流程测试"""    # todo
        res = get_bookId['data']['content']
        readBookIds = DataFrame(res)["id"].tolist()
        pl = {
            "readBookIds": readBookIds,
            "currentBookId": readBookIds[0],
            "recommendCount": len(readBookIds),
            "recommendationFocus": "similar"
        }
        res = self.book.storybookRecommend(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

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
        """获取故事书推荐-权限测试"""  # todo
        res = self.book.storybookRecommend(authorization=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_book_positive_bookDetailUrl_ok(self, get_bookId):
        """通过bookId获取书籍内容的下载链接-正向用例"""
        books_res = get_bookId['data']['content']
        for book in books_res:
            if book['bookName'] == 'Little Ray':
                bookId = book['id']
                bookKey = book['bookKey']
                break
        # 登陆状态，通过bookId获取书籍内容的下载链接
        res = self.book.bookDetailUrl(self.authorization, bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
        assert res['data']['url'] == 'https://static' + base_url.replace('creator', '') + '/'+ bookKey

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_bookDetailUrl(self, desc, value, get_bookId):
        """通过bookId获取书籍内容的下载链接-权限测试"""
        books_res = get_bookId['data']['content']
        for book in books_res:
            if book['bookName'] == 'Little Ray':
                bookId = book['id']
                bookKey = book['bookKey']
                break
        # 游客状态，通过bookId获取书籍内容的下载链接
        res = self.book.bookDetailUrl(value, bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
        assert res['data']['url'] == 'https://static' + base_url.replace('creator', '') + '/'+ bookKey

    @pytest.mark.smoke
    def test_book_positive_coverDetailUrl_ok(self, get_bookId):
        """通过bookId获取书籍封面的下载链接-正向用例"""
        books_res = get_bookId['data']['content']
        for book in books_res:
            if book['bookName'] == 'Little Ray':
                bookId = book['id']
                coverKey = book['coverKey']
                break
        res = self.book.coverDetailUrl(self.authorization, bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
        assert res['data']['url'] == 'https://static' + base_url.replace('creator', '') + '/' + coverKey

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_coverDetailUrl(self, desc, value):
        """通过bookId获取书籍封面的下载链接-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.book.coverDetailUrl(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_book_positive_getNarrationData_ok(self, get_bookId):
        """获取故事书的领读数据-正向用例"""
        books_res = self.book.book_list(self.authorization)['data']['content']
        for book in books_res:
            if book['bookName'] == 'Little Ray':
                bookId = book['id']
                break
        else:
            assert False, "未找到《Little Ray》这本书！"

        res = self.book.getNarrationData(self.authorization, bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['enabled']

        for book in books_res:
            if book['bookName'] == 'hq_test':
                bookId = book['id']
                break
        else:
            assert False, "未找到《hq_test》这本书！"
        res1 = self.book.getNarrationData(self.authorization, bookId)
        assert isinstance(res1, dict), f'接口返回类型异常: {type(res1)}'
        assert res1['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res1['code']}】"
        assert res1['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res1['message']}】"
        assert res1['data']['bookId'] == int(bookId)
        assert res1['data']['learningLanguage'] == 'en'
        assert res1['data']['narrationLanguage'] == 'zh'

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_getNarrationData(self, desc, value):
        """获取故事书的领读数据-权限测试"""
        res = self.book.getNarrationData(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_book_positive_save_narration_ok(self):
        """保存故事书的领读数据-正向用例"""
        # 列出当前用户创建的书籍列表中，找到书名称hq_test的故事书做测试
        books_res = self.book.book_list(self.authorization)['data']['content']
        for book in books_res:
            if book['bookName'] == 'hq_test':
                bookId = book['id']
                break
        else:
            assert False, "未找到《hq_test》这本书！"
        # 保存故事书的领读数据
        narrationData = [
            {
                "page": 1,
                "narration": "第一页内容"
            }
        ]
        save_res = self.book.save_narration(self.authorization, bookId, narrationData)
        assert isinstance(save_res, dict), f'接口返回类型异常: {type(save_res)}'
        assert save_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{save_res['code']}】"
        assert save_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{save_res['message']}】"
        assert save_res['data']['message'] == '领读数据保存任务已启动，正在后台处理中'
        assert save_res['data']['bookId'] == int(bookId)
        assert save_res['data']['narrationLanguage'] == 'zh'
        # 保存故事书的领读数据后，获取故事书的领读数据，验证故事书的领读数据保存成功
        get_res = self.book.getNarrationData(self.authorization, bookId)
        assert get_res['data']['bookId'] == int(bookId)
        assert get_res['data']['learningLanguage'] == 'en'
        assert get_res['data']['narrationLanguage'] == 'zh'
        narrationDataJson = json.loads(get_res['data']['narrationDataJson'])
        narration = narrationDataJson[0]['narration']
        assert narration == "第一页内容", "故事书的领读数据保存失败！"

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_save_narration(self, desc, value):
        """保存故事书的领读数据-权限测试"""
        res = self.book.save_narration(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    @pytest.mark.parametrize('enabled', [True, False])
    def test_book_positive_narration_setEnabled_ok(self, enabled):
        """设置故事书领读的启用状态-正向用例"""
        # 列出当前用户创建的书籍列表中，找到书名称hq_test的故事书做测试
        books_res = self.book.book_list(self.authorization)['data']['content']
        for book in books_res:
            if book['bookName'] == 'hq_test':
                bookId = book['id']
                break
        else:
            assert False, "未找到《hq_test》这本书！"
        # 设置故事书领读的启用状态-开启或关闭
        res = self.book.narration_setEnabled(self.authorization, bookId, enabled)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['bookId'] == int(bookId)
        assert res['data']['enabled'] == enabled
        assert res['data']['message'] == '领读启用状态已更新'

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_narration_setEnabled(self, desc, value):
        """设置故事书领读的启用状态-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.book.narration_setEnabled(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_book_positive_regenerate_narration_ok(self):
        """重新生成故事书的领读数据-正向用例"""
        # 列出当前用户创建的书籍列表中，找到书名称hq_test的故事书做测试
        books_res = self.book.book_list(self.authorization)['data']['content']
        for book in books_res:
            if book['bookName'] == 'hq_test':
                bookId = book['id']
                break
        else:
            assert False, "未找到《hq_test》这本书！"
        # 重新生成故事书的领读数据
        res = self.book.regenerate_narration(self.authorization, bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['bookId'] == int(bookId)
        assert res['data']['message'] == '领读数据重新生成任务已启动'

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_regenerate_narration(self, desc, value):
        """重新生成故事书的领读数据-权限测试"""
        res = self.book.regenerate_narration(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_book_positive_manul_narration_ok(self):
        """保存故事书的领读数据-正向用例"""
        # 列出当前用户创建的书籍列表中，找到书名称hq_test的故事书做测试
        books_res = self.book.book_list(self.authorization)['data']['content']
        for book in books_res:
            if book['bookName'] == 'hq_test':
                bookId = book['id']
                break
        else:
            assert False, "未找到《hq_test》这本书！"

        # 保存故事书的领读数据
        narrationData = [
            {
                "page": 2,
                "narration": "第一页内容"
            }
        ]
        save_res = self.book.save_narration(self.authorization, bookId, narrationData)
        assert isinstance(save_res, dict), f'接口返回类型异常: {type(save_res)}'
        assert save_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{save_res['code']}】"
        assert save_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{save_res['message']}】"
        assert save_res['data']['message'] == '领读数据保存任务已启动，正在后台处理中'
        assert save_res['data']['bookId'] == int(bookId)
        assert save_res['data']['narrationLanguage'] == 'zh'
        # 关闭设置故事书领读
        enable_res = self.book.narration_setEnabled(self.authorization, bookId, enabled=False)
        assert enable_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{enable_res['code']}】"
        # 关闭设置故事书领读后，获取故事书的领读数据，验证无法查看领读数据
        get_res1 = self.book.getNarrationData(self.authorization, bookId)
        assert not get_res1['data']['enabled']
        # 启用设置故事书领读
        enable_res = self.book.narration_setEnabled(self.authorization, bookId)
        assert enable_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{enable_res['code']}】"
        # 启用设置故事书领读后，获取故事书的领读数据，验证故事书的领读数据保存成功
        get_res2 = self.book.getNarrationData(self.authorization, bookId)
        assert get_res2['data']['bookId'] == int(bookId)
        assert get_res2['data']['learningLanguage'] == 'en'
        assert get_res2['data']['narrationLanguage'] == 'zh'
        assert get_res2['data']['enabled'] == True
        narrationDataJson = json.loads(get_res2['data']['narrationDataJson'])
        narration = narrationDataJson[0]['narration']
        assert narration == "第一页内容", "故事书的领读数据保存失败！"

    @pytest.mark.smoke
    def test_book_positive_ai_narration_ok(self):
        """重新生成故事书的领读数据-正向用例"""
        # 列出当前用户创建的书籍列表中，找到书名称hq_test的故事书做测试
        books_res = self.book.book_list(self.authorization)['data']['content']
        for book in books_res:
            if book['bookName'] == 'hq_test':
                bookId = book['id']
                break
        else:
            assert False, "未找到《hq_test》这本书！"
        # 重新生成故事书的领读数据
        regenerate_res = self.book.regenerate_narration(self.authorization, bookId)
        assert regenerate_res['data']['message'] == '领读数据重新生成任务已启动'
        # 关闭设置故事书领读
        enable_res = self.book.narration_setEnabled(self.authorization, bookId, enabled=False)
        assert enable_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{enable_res['code']}】"
        # 关闭设置故事书领读后，获取故事书的领读数据，验证无法查看领读数据
        get_res1 = self.book.getNarrationData(self.authorization, bookId)
        assert not get_res1['data']['enabled']
        # 启用设置故事书领读
        enable_res = self.book.narration_setEnabled(self.authorization, bookId)
        assert enable_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{enable_res['code']}】"
        # 启用设置故事书领读后，获取故事书的领读数据，验证故事书的领读数据保存成功
        get_res2 = self.book.getNarrationData(self.authorization, bookId)
        assert get_res2['data']['bookId'] == int(bookId)
        assert get_res2['data']['learningLanguage'] == 'en'
        assert get_res2['data']['narrationLanguage'] == 'zh'
        assert get_res2['data']['enabled'] == True
        narrationDataJson = json.loads(get_res2['data']['narrationDataJson'])
        narration = narrationDataJson[0]['narration']
        assert narration, "故事书的领读数据保存失败！"
        
    @pytest.mark.release
    def test_book_positive_lexiLelevelMapping_ok(self):
        """获取蓝思分数等级映射关系-前端下拉筛选用 – 等级枚举一致性"""
        res = self.book.lexiLelevelMapping(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        for _data in res['data']:
            if _data == "A":
                assert _data['inclusiveMax'] == True
                assert _data['inclusiveMin'] == False
                assert _data['max'] == 200
                assert _data['min'] == 0

    @pytest.mark.release
    def test_book_positive_getQuerybyfilter_ok(self):
        """根据等级和认证过滤查询书籍-正向用例"""
        res = self.book.getQuerybyfilter(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
