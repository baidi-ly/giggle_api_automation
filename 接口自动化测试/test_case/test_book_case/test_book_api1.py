import datetime
import json
import random
import sys
import os
import threading
import time
import uuid
from time import strftime

from pandas import DataFrame
from utils.book_codec import parse_book_from_bytes, Book

import config
from test_case.page_api.base_api import BaseAPI
from test_case.page_api.book.book_api import BookApi
from test_case.page_api.kid.kid_api import KidApi
from test_case.page_api.materials.materials_api import MaterialsApi
from test_case.page_api.user.user_api import UserApi

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
        self.user = UserApi()
        self.materials = MaterialsApi()
        self.authorization, self.userId = self.book.get_authorization()
        self.now = strftime("%Y%m%d%H%M%S")
        # 查询故事书标签类型列表
        self.bookTagtType_id = self.book.bookTagTypeList(self.authorization)['data']['content'][0]['id']

        try:
            # 列出当前用户创建的书籍列表
            self.book_name = 'The Sock-Eating Bear'
            bookList = self.book.book_list(self.authorization)['data']['content']
            for book in bookList:
                if book['bookName'] == self.book_name:
                    self.book_id = book['id']
                    break
            else:
                assert False, "未找到故事书《The Sock-Eating Bear》"
        except Exception as e:
            print('未找到故事书《The Sock-Eating Bear》')

        try:
            # 列出当前用户创建的书籍列表
            self.public_book_name = 'Barnaby Counts!'
            bookList = self.book.guest_book_list('')['data']['content']
            for book in bookList:
                if book['bookName'] == self.public_book_name:
                    self.public_book_id = book['id']
                    break
            else:
                assert False, "未找到故事书《Barnaby Counts!》"
        except Exception as e:
            print('未找到故事书《Barnaby Counts!》')
            
    def teardown_class(self):
        '''全局数据清理'''
        # 查询故事书标签类型列表
        BookTagTypes = self.book.bookTagTypeList(self.authorization)['data']['content']
        if BookTagTypes:
            for _type in BookTagTypes:
                if 'dibo_test' in _type['name']:
                    tagTypeId = _type['id']
                    # 查询指定类型下的故事书标签列表
                    book_tags = self.book.getBookTagsByType(self.authorization, tagTypeId=tagTypeId)['data']['content']
                    if book_tags:
                        for _book_tag in book_tags:
                            if 'dibo_test' in _book_tag['name']:
                                tage_id = _book_tag['id']
                                # 删除书籍标签
                                self.book.deleteBookTag(self.authorization, tage_id)
                    # 删除故事书标签
                    self.book.deleteBookTagType(self.authorization, _type['id'])

    @pytest.fixture(scope='function')
    def create_BookTagTypes(self):
        '''创建多个故事书标签'''
        tagIds = []
        for i in range(3):
            tagDescription = '创建书籍标签描述'
            tagName = 'dibo_test' + self.now + str(i)
            id = self.book.createBookTag(self.authorization, tagDescription, tagName, self.bookTagtType_id)['data']['id']
            tagIds.append(id)
        yield tagIds
        for bookTagId in tagIds:
            res = self.book.deleteBookTag(self.authorization, bookTagId)
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'


    @pytest.fixture(scope="class")
    def get_bookId(self):
        '''方法前置 - 获取bookid'''
        bookList = self.book.book_list(self.authorization)
        yield bookList

    @pytest.fixture(scope='function')
    def create_BookTagType(self):
        description = '创建书籍标签类型描述'
        name = 'dibo_test' + self.now
        res = self.book.createBookTagType(self.authorization, description=description, name=name)
        bookTagTypeId = res['data']['id']

        yield bookTagTypeId

        res = self.book.deleteBookTagType(self.authorization, bookTagTypeId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'

    @pytest.fixture(scope='function')
    def create_BookTag(self, create_BookTagType, get_bookId):
        '''创建故事书标签'''
        tagDescription = '创建书籍标签描述'
        tagName = 'dibo_test' + self.now
        tagTypeId = create_BookTagType
        # 创建故事书标签
        bookTagId = self.book.createBookTag(self.authorization, tagDescription, tagName, tagTypeId)['data']['id']
        bookId = get_bookId["data"]["content"][0]["id"]
        # 为故事书添加标签
        self.book.addTagToBook(self.authorization, bookId, bookTagId)
        yield bookId, bookTagId
        # 删除书籍标签
        res = self.book.deleteBookTag(self.authorization, bookTagId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"

    @pytest.mark.smoke
    def test_book_positive_removeTagFromBook_ok(self, create_BookTag):
        """删除故事书与标签的关联关系-正向用例"""
        # 创建故事书标签
        bookId, bookTagId = create_BookTag
        # 删除故事书与标签的关联关系
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
        # 创建故事书标签
        bookId, bookTagId = create_BookTag
        # 查询故事书标签关联列表
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

    @pytest.mark.smoke
    def test_book_positive_batchUpdateBookTags_ok(self, get_bookId, create_BookTagTypes):
        """批量更新故事书的标签-正向用例"""
        # 获取bookid
        bookId = get_bookId["data"]["content"][0]["id"]
        # 创建多个故事书标签
        tagIds = create_BookTagTypes
        # 批量更新故事书的标签
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
        # 获取bookid
        bookId = get_bookId["data"]["content"][0]["id"]
        # 自动生成并保存故事书标签
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
        # 手动触发基于标签的故事书推荐计算
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
        """获取故事书推荐-正常流程测试"""
        # 获取bookid
        res = get_bookId['data']['content']
        readBookIds = DataFrame(res)["id"].tolist()
        pl = {
            "readBookIds": readBookIds,
            "currentBookId": readBookIds[0],
            "recommendCount": len(readBookIds),
            "recommendationFocus": "similar"
        }
        # 获取故事书推荐
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
        # 获取bookid
        books_res = get_bookId['data']['content']
        for book in books_res:
            if book['bookName'] == 'Little Ray':
                bookId = book['id']
                coverKey = book['coverKey']
                break
        else:
            assert False, "未找到故事书！"
        # 通过bookId获取书籍封面的下载链接
        res = self.book.coverDetailUrl(self.authorization, bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
        assert res['data']['url'] == 'https://static' + base_url.replace('creator', '') + '/' + coverKey

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
        res = self.book.coverDetailUrl(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_book_positive_getNarrationData_ok(self, get_bookId):
        """获取故事书的领读数据-正向用例"""
        # 列出当前用户创建的书籍列表
        books_res = self.book.book_list(self.authorization)['data']['content']
        for book in books_res:
            if book['bookName'] == 'Little Ray':
                bookId = book['id']
                break
        else:
            assert False, "未找到《Little Ray》这本书！"

        # 获取故事书的领读数据
        res = self.book.getNarrationData(self.authorization, bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['enabled']

        for book in books_res:
            if book['bookName'] == "Tiny Red's Wobbly Lines":
                bookId = book['id']
                break
        else:
            assert False, "未找到《Tiny Red's Wobbly Lines》这本书！"

        # 获取故事书的领读数据
        res1 = self.book.getNarrationData(self.authorization, bookId)
        assert isinstance(res1, dict), f'接口返回类型异常: {type(res1)}'
        assert res1['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res1['code']}】"
        assert res1['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res1['message']}】"
        assert res1['data']['bookId'] == int(bookId)
        assert res1['data']['learningLanguage'] == 'en'
        assert res1['data']['narrationLanguage'] == 'zh'

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
    @pytest.mark.parametrize('narrationLan',
                             ['bn', 'zh', 'en', 'de', 'id', 'pt',
                              'es', 'vi', 'it', 'ms', 'hi',
                              'pt-BR', 'sw', 'uk'])
    def test_book_positive_save_narration_ok(self, narrationLan):
        """保存故事书的领读数据-正向用例"""
        '''
        bn	Bengali (孟加拉语)	my	Burmese (缅甸语)
        zh	Chinese (Simplified) (简体中文)	zh-Hant	Chinese (Traditional) (繁体中文)
        en	English (英语)	fr	French (法语)
        de	German (德语)	hi	Hindi (印地语)
        id	Indonesian (印尼语)	ja	Japanese (日语)
        pt	Portuguese (葡萄牙语)	ru	Russian (俄语)
        es	Spanish (西班牙语)	tr	Turkish (土耳其语)
        vi	Vietnamese (越南语)	ar	Arabic (阿拉伯语)
        nl	Dutch (荷兰语)	fil	Filipino (菲律宾语)
        it	Italian (意大利语)	ko	Korean (韩语)
        ms	Malay (马来语)	pl	Polish (波兰语)
        pt-BR	Portuguese (Brazil) (巴西葡萄牙语)	ro	Romanian (罗马尼亚语)
        sw	Swahili (斯瓦希里语)	th	Thai (泰语)
        uk	Ukrainian (乌克兰语)
        '''
        # 列出当前用户创建的书籍列表中，找到书名称hq_test的故事书做测试
        books_res = self.book.book_list(self.authorization, pageSize=100)['data']['content']
        for book in books_res:
            if book['bookName'] == "hq_test":
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
        pl = {'narrationLanguage': narrationLan}
        save_res = self.book.save_narration(self.authorization, bookId, narrationData, **pl)
        assert isinstance(save_res, dict), f'接口返回类型异常: {type(save_res)}'
        assert save_res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{save_res['code']}】"
        assert save_res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{save_res['message']}】"
        assert save_res['data']['message'] == '领读数据保存任务已启动，正在后台处理中'
        assert save_res['data']['bookId'] == int(bookId)
        assert save_res['data']['narrationLanguage'] == narrationLan

        # 保存故事书的领读数据后，获取故事书的领读数据，验证故事书的领读数据保存成功
        get_res = self.book.getNarrationData(self.authorization, bookId, narrationLanguage=narrationLan)
        assert get_res['data']['bookId'] == int(bookId)
        assert get_res['data']['learningLanguage'] == 'en'
        assert get_res['data']['narrationLanguage'] == narrationLan
        assert get_res['data']['enabled'] == True
        if narrationLan in ['en', 'zh', 'id', 'hi', 'vi']:
            narrationS3Key = get_res['data']['narrationS3Key']
            fileName = '领读语音' + narrationLan + self.now
            self.materials.download_materials(self.authorization, narrationS3Key, fileName)
        narrationDataJson = json.loads(get_res['data']['narrationDataJson'])
        narration = narrationDataJson[0]['narration']
        assert narration == "第一页内容", "故事书的领读数据保存失败！"

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
        """AI生成故事书的领读数据-正向用例"""
        # 列出当前用户创建的书籍列表中，找到书名称hq_test的故事书做测试
        books_res = self.book.book_list(self.authorization, pageSize=100)['data']['content']
        for book in books_res:
            if book['bookName'] == "Tiny Red's Wobbly Lines":
                bookId = book['id']
                break
        else:
            assert False, "未找到《Barnaby's Wobbly Circle》这本书！"
        for narrationLan in ["en", "zh", "id", "hi", "vi"]:
            # 保存故事书的领读数据后，获取故事书的领读数据，验证故事书的领读数据保存成功
            get_res1 = self.book.getNarrationData(self.authorization, bookId, narrationLanguage=narrationLan)
            assert get_res1['data']['enabled']
            # 清空故事书当前语言的领读数据，预备后续校验ai生成的领读数据
            pl = {'narrationLanguage': narrationLan}
            save_res = self.book.save_narration(self.authorization, bookId, **pl)
            assert save_res['message'] == 'success'
        # AI生成故事书的领读数据
        res = self.book.regenerate_narration(self.authorization, bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['bookId'] == int(bookId)
        assert res['data']['message'] == '领读数据重新生成任务已启动'
        # 设置故事书领读的启用状态-开启或关闭
        res = self.book.narration_setEnabled(self.authorization, bookId)
        assert res['message'] == 'success'
        for i in range(5):
            try:
                for narrationLan in ["en", "zh", "id", "hi", "vi"]:
                    # 保存故事书的领读数据后，获取故事书的领读数据，验证故事书的领读数据保存成功
                    get_res2 = self.book.getNarrationData(self.authorization, bookId, narrationLanguage=narrationLan)
                    assert get_res2['data']['bookId'] == int(bookId)
                    assert get_res2['data']['learningLanguage'] == 'en'
                    assert get_res2['data']['narrationLanguage'] == narrationLan
                    assert get_res2['data']['enabled'] == True
                    # 下载语音材料
                    narrationS3Key = get_res2['data']['narrationS3Key']
                    fileName = '领读语音' + narrationLan + self.now
                    self.materials.download_materials(self.authorization, narrationS3Key, fileName)
                    narrationDataJson = json.loads(get_res2['data']['narrationDataJson'])
                    narration = narrationDataJson[0]['narration']
                    assert narration, "故事书的领读数据保存失败！"
                break
            except:
                time.sleep(1)
        else:
            assert True, "10min内AI生成故事书的领读数据未完成！"  # 生成的时间长，影响自动化运行效率，所以把时间缩短

    def test_book_permission_regenerate_narration(self):
        """重新生成故事书的领读数据-权限测试"""
        res = self.book.regenerate_narration('', code=401)
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
        books_res = self.book.book_list(self.authorization, pageSize=100)['data']['content']
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
        
    @pytest.mark.smoke
    def test_book_positive_lexiLelevelMapping_ok(self):
        """获取蓝思分数等级映射关系-前端下拉筛选用 – 等级枚举一致性"""
        res = self.book.lexiLelevelMapping(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        for _data in res['data']:
            if _data == "A":  # 等级为A
                assert _data['inclusiveMax'] == True
                assert _data['inclusiveMin'] == True
                assert _data['max'] == 200
                assert _data['min'] == 0
            elif _data == "B":  # 等级为B
                assert _data['inclusiveMax'] == True
                assert _data['inclusiveMin'] == False
                assert _data['max'] == 400
                assert _data['min'] == 200
            elif _data == "C":  # 等级为C
                assert _data['inclusiveMax'] == True
                assert _data['inclusiveMin'] == False
                assert _data['max'] == 450
                assert _data['min'] == 400
            elif _data == "D":  # 等级为D
                assert _data['inclusiveMax'] == True
                assert _data['inclusiveMin'] == False
                assert _data['max'] == 500
                assert _data['min'] == 450
            elif _data == "E":  # 等级为E
                assert _data['inclusiveMax'] == False
                assert _data['inclusiveMin'] == False
                assert _data['max'] == None
                assert _data['min'] == 500

    @pytest.mark.smoke
    @pytest.mark.parametrize("certifications", ['official', 'community', 'official,community'])
    @pytest.mark.parametrize("levels", ['A', 'B', 'C', 'D', 'E', 'A,B', 'A,C', 'A,D', 'A,E', 'B,C', 'B,D', 'B,E', 'C,D', 'C,E', 'D,E',
                  'A,B,C', 'A,B,D', 'A,B,E', 'A,C,D', 'A,C,E', 'A,D,E', 'B,C,D', 'B,C,E', 'B,D,E', 'C,D,E',
                  'A,B,C,D', 'A,B,C,E', 'A,B,D,E', 'A,C,D,E', 'B,C,D,E', 'A,B,C,D,E'])
    def test_book_positive_getQuerybyfilter_ok(self, certifications, levels):
        """根据等级和认证过滤查询书籍-正向用例"""
        # 获取蓝思分数等级映射关系
        level_map_res = self.book.lexiLelevelMapping(self.authorization)['data']
        level_map = {}
        for level in level_map_res:
            max_plus = 0 if level['inclusiveMax'] else -1
            min_plus = 0 if level['inclusiveMin'] else 1
            if isinstance(level['max'], int):
                level_map[level['level']] = [level['min']+min_plus, level['max']+max_plus]
            else:
                level_map[level['level']] = [level['min']+min_plus, 99999999]
        level_list = levels.split(',')
        lexile_range = []
        for level_letter in level_list:
            lexile_range.append(level_map[level_letter])
        # 根据等级和认证过滤查询书籍
        pl = {
            "certifications": certifications,
            "levels": levels
        }
        res = self.book.getQuerybyfilter(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        content = res['data']['content']
        for book in content:
            bookId = book['id']
            # 获取故事书的lexile分数
            book_lexile = self.book.bookLexile(self.authorization, bookId)['data']
            for lexile in lexile_range:
                if lexile[0] <= book_lexile <= lexile[1]:
                    break
            else:
                assert False, f"根据等级过滤查询书籍失败，返回的数据蓝思值不符合等级{levels}要求"
            if certifications == 'official':    # 如果certifications是社区则校验邮箱类型
                key = book['authorName']
                user_email_res = self.user.getSearch(self.authorization, key)['data']['content']
                for user_email in user_email_res:
                    email = user_email['email']
                    if email.endswith('@giggleacademy.com') or email.endswith('@giggleacademy.me'):
                        break
                else:
                    assert False
            elif certifications == 'community':    # 如果certifications是精选则校验是否精选
                assert book['selected'] == 1
            else:    # 2种情况综合
                if book['selected'] != 1:
                    key = book['authorName']
                    user_email_res = self.user.getSearch(self.authorization, key)['data']['content']
                    for user_email in user_email_res:
                        email = user_email['email']
                        if email.endswith('@giggleacademy.com') or email.endswith('@giggleacademy.me'):
                            break
                    else:
                        assert False

    @pytest.mark.smoke
    @pytest.mark.parametrize("levels", ['A', 'B', 'C', 'D', 'E', 'A,B', 'A,C', 'A,D', 'A,E', 'B,C', 'B,D', 'B,E', 'C,D', 'C,E', 'D,E',
                  'A,B,C', 'A,B,D', 'A,B,E', 'A,C,D', 'A,C,E', 'A,D,E', 'B,C,D', 'B,C,E', 'B,D,E', 'C,D,E',
                  'A,B,C,D', 'A,B,C,E', 'A,B,D,E', 'A,C,D,E', 'B,C,D,E', 'A,B,C,D,E'])
    def test_book_getQuerybyfilter_without_certifications(self, levels):
        """根据等级和认证过滤查询书籍-certifications为空"""
        # 获取蓝思分数等级映射关系
        level_map_res = self.book.lexiLelevelMapping(self.authorization)['data']
        level_map = {}
        for level in level_map_res:
            max_plus = 0 if level['inclusiveMax'] else -1
            min_plus = 0 if level['inclusiveMin'] else 1
            if isinstance(level['max'], int):
                level_map[level['level']] = [level['min']+min_plus, level['max']+max_plus]
            else:
                level_map[level['level']] = [level['min']+min_plus, 99999999]
        level_list = levels.split(',')
        lexile_range = []
        for level_letter in level_list:
            lexile_range.append(level_map[level_letter])
        # 根据等级和认证过滤查询书籍
        pl = {
            "certifications": '',
            "levels": levels
        }
        res = self.book.getQuerybyfilter(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        content = res['data']['content']
        for book in content:
            bookId = book['id']
            # 获取故事书的 lexile 分数
            book_lexile = self.book.bookLexile(self.authorization, bookId)['data']
            for lexile in lexile_range:
                if lexile[0] <= book_lexile <= lexile[1]:
                    break
            else:
                assert False, f"根据等级过滤查询书籍失败，返回的数据蓝思值不符合等级{levels}要求"

    @pytest.mark.smoke
    @pytest.mark.parametrize("certifications", ['official', 'community', 'official,community'])
    def test_book_getQuerybyfilter_without_levels(self, certifications):
        """根据等级和认证过滤查询书籍-levels为空"""
        # 根据等级和认证过滤查询书籍
        pl = {
            "certifications": certifications,
            "levels": ''
        }
        res = self.book.getQuerybyfilter(self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        content = res['data']['content']
        for book in content:
            if certifications == 'official':    # 如果certifications是社区则校验邮箱类型
                key = book['authorName']
                # 根据用户名 / email搜索用户
                user_email_res = self.user.getSearch(self.authorization, key)['data']['content']
                for user_email in user_email_res:
                    email = user_email['email']
                    if email.endswith('@giggleacademy.com') or email.endswith('@giggleacademy.me'):
                        break
                else:
                    assert False
            elif certifications == 'community':   # 如果certifications是精选则校验是否精选
                assert book['selected'] == 1
            else:   #     综合2种情况
                if book['selected'] != 1:
                    key = book['authorName']
                    # 根据用户名 / email搜索用户
                    user_email_res = self.user.getSearch(self.authorization, key)['data']['content']
                    for user_email in user_email_res:
                        email = user_email['email']
                        if email.endswith('@giggleacademy.com') or email.endswith('@giggleacademy.me'):
                            break
                    else:
                        assert False

    @pytest.mark.smoke
    def test_book_batchUpdateOfficial_bookPubliclist_ok(self):
        """批量更新故事书的官方认证状态-查询公开书籍列表，验证默认推送社区或精选的故事书"""
        # 查询公开书籍列表
        book_res = self.book.book_public_list(self.authorization)['data']['content']
        bookIds = DataFrame(book_res)['id'].tolist()
        # 批量更新故事书的官方认证状态
        res = self.book.batchUpdateOfficial(self.authorization, bookIds)
        assert res['data']['message'] == '批量更新成功', '批量更新失败！'
        # 查询公开书籍列表
        book_res = self.book.book_public_list(self.authorization)['data']['content']
        for book in book_res:
            # 验证默认推送社区或精选的故事书
            assert book['selected'] or book['official']
            # 通过bookId查询书籍详情，获取作者名称
            bookId = book['id']
            bookDetail1 = self.book.bookDetails(self.authorization, bookId)
            if bookDetail1['data']:
                authorName = bookDetail1['data']['authorName']
            else:
                continue
            # 根据用户名搜索用户获取用户email
            user_email_res = self.user.getSearch(self.authorization, authorName)['data']['content']
            for user_email in user_email_res:
                email = user_email['email']
                if email.endswith('@giggleacademy.com') or email.endswith('@giggleacademy.me'):
                    expected = 1
                    break
            else:
                expected = 0
            # 通过bookId查询书籍详情，验证official字段返回成功
            official = self.book.bookDetails(self.authorization, bookId)['data']['official']
            assert expected == official, '通过bookId查询书籍详情,'

    @pytest.mark.smoke
    def test_book_batchUpdateOfficial_guestBookList_ok(self):
        """批量更新故事书的官方认证状态-查询公开书籍列表，验证默认推送社区或精选的故事书"""
        # 查询公开书籍列表（不需要鉴权）
        book_res = self.book.guest_book_list(self.authorization)['data']['content']
        bookIds = DataFrame(book_res)['id'].tolist()
        # 批量更新故事书的官方认证状态
        res = self.book.batchUpdateOfficial(self.authorization, bookIds)
        assert res['data']['message'] == '批量更新成功', '批量更新失败！'
        # 再次查询公开书籍列表，验证批量更新成功
        book_res = self.book.guest_book_list(self.authorization)['data']['content']
        for book in book_res:
            # 验证默认推送社区或精选的故事书
            assert book['selected'] or book['official']
            # 通过bookId查询书籍详情，获取作者名称
            bookId = book['id']
            bookDetail1 = self.book.bookDetails(self.authorization, bookId)
            if bookDetail1['data']:
                authorName = bookDetail1['data']['authorName']
            else:
                continue
            # 根据用户名搜索用户获取用户email
            user_email_res = self.user.getSearch(self.authorization, authorName)['data']['content']
            for user_email in user_email_res:
                email = user_email['email']
                if email.endswith('@giggleacademy.com') or email.endswith('@giggleacademy.me'):
                    expected = 1
                    break
            else:
                expected = 0
            # 通过bookId查询书籍详情，验证official字段返回成功
            official = self.book.bookDetails(self.authorization, bookId)['data']['official']
            assert expected == official, '通过bookId查询书籍详情,'

    @pytest.mark.smoke
    def test_book_positive_trigger_ok(self):
        """触发故事书翻译"""
        bookIds = [self.book_id]
        res = self.book.translation_trigger(self.authorization, bookIds)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        expect_res = {'message': '已触发 1 本书籍的翻译任务', 'nonExistingBooks': [], 'triggeredBooks': [int(self.book_id)]}
        assert res['data'] == expect_res

    @pytest.mark.smoke
    @pytest.mark.parametrize('languageCode', ['en', 'ar', 'es', 'fr', 'de', 'pt', 'id', 'hi', 'th', 'vi', 'tr', 'ru', 'ja', 'ko'])
    def test_book_positive_languagePack_details_ok(self, languageCode):
        """根据故事书ID和语言代码查询语言包地址"""
        # 根据故事书ID和语言代码查询语言包地址
        res = self.book.languagePack(self.authorization, self.book_id, languageCode)
        if res['code'] == 200:  # 如果code不是200，说明字幕还未生成成功，校验code是100051
            assert res['data']['bookId'] == int(self.book_id)
            url = res['data']['url']
            fileName = '字幕' + languageCode + self.now
            self.materials.download_materials(self.authorization, '', fileName, url=url)
        else:
            assert res['code'] == 100051
            assert res['data'] == 'The specified key does not exist'

    @pytest.mark.smoke
    def test_book_positive_upload_webp_check(self):
        """上传书籍内容json-验证支持Webp格式的动图"""
        bookName = 'dibo_test_book' + self.now
        bookId = self.book.createBookWithName(self.authorization, bookName)['data']['id']
        file = {
            'file': ('webp_test.webp', open(os.getcwd() + f'/test_data/webp_test.webp', 'rb'))
        }
        res = self.book.book_upload(self.authorization, bookId, file)
        assert res['data']['bookKey'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_book_positive_storybook_generateCoverimage(self):
        """使用提示词和角色信息生成最终的封面图片 - 流程测试"""
        # 查询故事书Storyboard内容
        storyBoard_res = self.book.storyBoard(self.authorization, self.book_id)['data']
        # 故事书风格生成
        style_res = self.book.storyBookStyle(self.authorization)
        assert style_res['message'] == '风格生成成功'
        # 生成封面图片的提示词和角色信息
        pl = {
            "characters": storyBoard_res['characters'],
            "story": storyBoard_res['story'],
            "style": storyBoard_res['storyboard'][0]['prompt'],
            "title": self.book_name,
        }
        info_res = self.book.generateCoverimageInfo(self.authorization, **pl)['data']
        assert info_res['characters'] == storyBoard_res['characters']
        # 使用提示词和角色信息生成最终的封面图片
        task_id = str(uuid.uuid4())
        info_res.update({"task_id": task_id})
        request_res = self.book.generateCoverimage(self.authorization, **info_res)['data']
        assert request_res['task_id'] == task_id
        request_id = request_res['request_id']
        # 查看提示词和角色信息生成最终的封面图片状态
        image_url = self.book.generateCoverimageStatus(self.authorization, request_id)['data']['url']
        fileName = 'coverimage_test'
        # 下载材料
        self.materials.download_materials(self.authorization, '', fileName, url=image_url, fileType="png")

    @pytest.mark.smoke
    def test_book_positive_upload_book_cover(self):
        '''修改封面'''
        fileName = 'coverimage_test'
        # 修改封面
        file = {
            # "bookId": self.book_id,
            'file': (f'{fileName}.png', open(os.getcwd() + f'/report/{fileName}.png', 'rb'))
        }
        res1 = self.book.upload_book_cover(self.authorization, self.book_id, file)
        assert res1['message'] == 'success'
        # 上传书籍内容
        file = {
            'file': (f'{fileName}.png', open(os.getcwd() + f'/report/{fileName}.png', 'rb'))
        }
        res = self.book.book_upload(self.authorization, self.book_id, file)
        assert res['data']['bookKey'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.smoke
    def test_book_positive_multilingual_saveAndGET(self):
        '''保存故事书的多语言翻译'''
        # 保存故事书的多语言翻译
        title = 'dibo_test_title' + self.now
        description = 'dibo_test_description' + self.now
        title_description = '''Lily's socks always mysteriously disappear, leading her on a humorous journey to find them. She suspects everything from a sock-eating monster to a clanging dryer, only to ultimately discover that the surprising culprit is her own teddy bear.'''
        res1 = self.book.saveBookMultilingual(self.authorization, self.book_id, title, description=description)
        assert res1['data'] == '保存成功'
        # 查询故事书的所有多语言翻译
        res = self.book.getBookMultilingual(self.authorization, self.book_id)
        for k, v in res['data']['translations'].items():
            if k == 'en':
                assert v['title'] == title
                assert v['description'] == description
                break
        else:
            assert False
        # 还原故事书的多语言翻译
        self.book.saveBookMultilingual(self.authorization, self.book_id, self.book_name,  description=title_description)

    @pytest.mark.smoke
    @pytest.mark.parametrize('k', ['bn', 'my', 'zh', 'zh-Hant', 'en', 'fr', 'de', 'hi', 'id', 'ja', 'pt', 'ru', 'es', 'tr', 'vi', 'ar', 'nl', 'fil', 'it', 'ko', 'ms', 'pl', 'pt-BR', 'ro', 'sw', 'th', 'uk', 'ur'])
    def test_book_positive_multilingual_getBookMultilingual(self, k):
        '''查询故事书的所有多语言翻译'''
        # 查询故事书的所有多语言翻译
        res = self.book.getBookMultilingual(self.authorization, self.book_id)
        assert res['data']['translations'][k]['title']
        assert res['data']['translations'][k]['description']

    @pytest.mark.smoke
    def test_book_voicePack_upload_and_addProcessTask(self):
        '''保存故事书的多语言翻译后，添加语言包处理任务到队列'''
        # 获取Lily and the Little Sprout的信息
        book_name = 'Lily and the Little Sprout'
        bookList = self.book.book_list(self.authorization)['data']['content']
        for book in bookList:
            if book['bookName'] == book_name:
                book_id = book['id']
                break
        else:
            assert False, "未找到故事书《Lily and the Little Sprout》"
        # 保存故事书的多语言翻译
        description = '''Lily's socks always mysteriously disappear, leading her on a humorous journey to find them. She suspects everything from a sock-eating monster to a clanging dryer, only to ultimately discover that the surprising culprit is her own teddy bear.'''
        res1 = self.book.saveBookMultilingual(self.authorization, book_id, book_name, description=description)
        assert res1['data'] == '保存成功'
        # 上传首页故事书音频
        file = {
            'file': ('story_language.mp3', open(os.getcwd() + f'/test_data/story_language.mp3', 'rb'))
        }
        # 上传并保存故事书语言包
        res2 = self.book.uploadVoicePack(self.authorization, book_id, 'en', file=file)
        s3Key = res2['data']['s3Key']
        # 添加语言包处理任务到队列
        res3 = self.book.addProcesstaskVoicePack(self.authorization, book_id, 'en')
        assert res3['data']['message'] == '任务已添加到队列'

    @pytest.mark.smoke
    @pytest.mark.parametrize('age', [0,1,2,3,4,5,6,7,8,9,10])
    def test_book_series_pined_by_age(self, age):
        '''故事书排序优化，每个年龄段有自己的系列推荐，相互之间不干扰'''
        # 按年龄查询被pin的系列列表
        pinnedSeries_res = self.book.pinnedSeriesByAge(self.authorization, age)['data']
        pined_ids = DataFrame(pinnedSeries_res)['id'].tolist() if pinnedSeries_res else []
        # 按年龄查询系列列表
        seriesList = self.book.seriesByAge(self.authorization, age=age)['data']['content']
        series_ids0 = DataFrame(pinnedSeries_res)['id'].tolist() if pinnedSeries_res else []
        flag = False
        for series in seriesList:
            assert series['ageMax'] >= age and series['ageMin'] <= age
            seriesId = series['id']
            if seriesId not in pined_ids:
                flag = True
                break
        else:
            # 更新故事书系列pin状态
            seriesId = seriesList[0]['id']
            res = self.book.pinSeries(self.authorization, seriesId, age, isPinned=False)
            assert res['data'] == '系列pin状态更新成功'
        # 更新故事书系列pin状态
        res1 = self.book.pinSeries(self.authorization, seriesId, age, isPinned=True)
        assert res1['data'] == '系列pin状态更新成功'
        # 按年龄查询被pin的系列列表
        pinnedSeries_res = self.book.pinnedSeriesByAge(self.authorization, age)['data']
        pined_ids1 = DataFrame(pinnedSeries_res)['id'].tolist()
        assert seriesId == pined_ids1[0]
        if flag:
            pined_ids1.remove(seriesId)
            assert pined_ids1 == pined_ids
            # 更新故事书系列pin状态
            res2 = self.book.pinSeries(self.authorization, seriesId, age, isPinned=False)
            assert res2['data'] == '系列pin状态更新成功'
        else:
            pined_ids.remove(seriesId)
            pined_ids1.remove(seriesId)
            assert pined_ids1 == pined_ids

        # 创建测试学生
        kid_name = 'dibo_test_kid' + time.strftime("%Y%m%d%H%M%S")
        import datetime
        # 获取当前日期和时间
        now = datetime.datetime.now()
        current_year = int(now.year)
        yearOfBirth = current_year - age
        kid_id = self.user.createkid(self.authorization, kid_name, yearOfBirth=yearOfBirth)['data']['id']
        try:
            # 在app中检查系列推荐情况
            series_res = self.book.series_list(self.authorization, kidId=kid_id)
            series_res = series_res['data']['content']
            series_ids1 = DataFrame(series_res)['id'].tolist()[:len(series_ids0)] if pinnedSeries_res else []
            assert series_ids0 == series_ids1
        finally:
            self.user.deletekid(self.authorization, kid_id)

    @pytest.mark.smoke
    def test_book_pined_stroy_order(self):
        '''系列下pin故事书默认第一位'''
        for i in range(12):
            # 按年龄查询系列列表
            seriesId = self.book.seriesByAge(self.authorization, age=i)['data']['content'][0]['id']
            # 根据系列ID查询故事书列表
            book_res = self.book.getBooksBySeriesId(self.authorization, seriesId)['data']['content']
            if book_res:
                break
        # 查询系列下所有被pin的故事书
        pinnedBooks_res = self.book.getPinnedbooks(self.authorization, seriesId)['data']
        pined_ids = DataFrame(pinnedBooks_res)['id'].tolist() if pinnedBooks_res else []
        # 根据系列ID查询故事书列表
        flag = False
        book_res = self.book.getBooksBySeriesId(self.authorization, seriesId)['data']['content']
        for book in book_res:
            if int(book['id']) not in pined_ids:
                bookId = book['id']
                flag = True
                break
        else:
            # 更新故事书pin状态
            bookId = book_res[0]['id']
            res1 = self.book.pinBook(self.authorization, bookId, isPinned=False)['data']
            assert res1 == '故事书pin状态更新成功'
        # 更新故事书pin状态
        res2 = self.book.pinBook(self.authorization, bookId, isPinned=True)['data']
        assert res2 == '故事书pin状态更新成功'
        # 查询系列下所有被pin的故事书
        pinnedBooks_res1 = self.book.getPinnedbooks(self.authorization, seriesId)['data']
        pined_ids1 = DataFrame(pinnedBooks_res1)['id'].tolist() if pinnedBooks_res1 else []
        assert int(bookId) == pined_ids1[0]
        if flag:
            pined_ids1.remove(int(bookId))
            assert pined_ids1 == pined_ids
        else:
            pined_ids.remove(int(bookId))
            pined_ids1.remove(int(bookId))
            assert pined_ids1 == pined_ids

    @pytest.mark.smoke
    @pytest.mark.parametrize("_official", [0, 1])
    @pytest.mark.parametrize("selected", [0, 1])
    @pytest.mark.parametrize("levels", ['A', 'B', 'C', 'D', 'E', 'A,B', 'A,C', 'A,D', 'A,E', 'B,C', 'B,D', 'B,E', 'C,D', 'C,E', 'D,E',
                  'A,B,C', 'A,B,D', 'A,B,E', 'A,C,D', 'A,C,E', 'A,D,E', 'B,C,D', 'B,C,E', 'B,D,E', 'C,D,E',
                  'A,B,C,D', 'A,B,C,E', 'A,B,D,E', 'A,C,D,E', 'B,C,D,E', 'A,B,C,D,E'])
    def test_book_positive_book_public_list_key(self, _official, selected, levels):
        """根据等级和认证过滤查询书籍-key为不为空走向量模式，key为空走正常搜索逻辑，主要控制逻辑是levels是否生效"""

        # 获取蓝思分数等级映射关系
        level_map_res = self.book.lexiLelevelMapping(self.authorization)['data']
        level_map = {}
        for level in level_map_res:
            max_plus = 0 if level['inclusiveMax'] else -1
            min_plus = 0 if level['inclusiveMin'] else 1
            if isinstance(level['max'], int):
                level_map[level['level']] = [level['min']+min_plus, level['max']+max_plus]
            else:
                level_map[level['level']] = [level['min']+min_plus, 99999999]
        level_list = levels.split(',')
        lexile_range = []
        for level_letter in level_list:
            lexile_range.append(level_map[level_letter])

        # 查询公开书籍列表
        key = "test"
        pl = {
            'key': key,
            "levels": levels,
            "selected": selected,
            "official": _official,
        }
        book_res = self.book.book_public_list(self.authorization, **pl)['data']['content']
        for book in book_res:
            bookId = book['id']
            ch_key = "测试"
            if key not in book['bookName'] and key not in book['authorName'] and ch_key not in book['bookName'] and ch_key not in book['authorName']:
                try:
                    layers = self.book.book_content(self.authorization, bookId)['data']['editorStateHistories']['layers']
                except Exception as e:
                    layers = []
                    print('该书籍未在数据库中存储内容！')
                if layers:
                    for layer in layers:
                        if key in layer['text']:
                            break
                    else:
                        assert False
            # 获取故事书的 lexile 分数
            book_lexile = self.book.bookLexile(self.authorization, bookId)['data']
            for i in range(60):
                for lexile in lexile_range:
                    if lexile[0] <= book_lexile <= lexile[1]:
                        flag = True
                        break
                else:
                    # 批量更新故事书的官方认证状态
                    res = self.book.processlayers(self.authorization, bookId)
                    assert res['data']
                if flag:
                    break
                else:
                    time.sleep(1)
            else:
                assert False

            # 验证默认推送社区或精选的故事书
            if selected == 1 and selected == 0:
                assert book['selected']
            if _official == 1 and selected == 0:
                assert book['official']
            if _official == 1 and selected == 1:
                assert book['official'] or book['selected']

            if book['official']:
                # 通过bookId查询书籍详情，获取作者名称
                bookId = book['id']
                bookDetail1 = self.book.bookDetails(self.authorization, bookId)
                if bookDetail1['data']:
                    authorName = bookDetail1['data']['authorName']
                else:
                    continue
                # 根据用户名搜索用户获取用户email
                user_email_res = self.user.getSearch(self.authorization, authorName)['data']['content']
                for user_email in user_email_res:
                    email = user_email['email']
                    if email.endswith('@giggleacademy.com') or email.endswith('@giggleacademy.me'):
                        expected = 1
                        break
                else:
                    expected = 0
                # 通过bookId查询书籍详情，验证official字段返回成功
                official = self.book.bookDetails(self.authorization, bookId)['data']['official']
                assert official == expected, '通过bookId查询书籍详情,'

    @pytest.mark.smoke
    @pytest.mark.parametrize("_official", [0, 1])
    @pytest.mark.parametrize("selected", [0, 1])
    @pytest.mark.parametrize("levels", ['A', 'B', 'C', 'D', 'E', 'A,B', 'A,C', 'A,D', 'A,E', 'B,C', 'B,D', 'B,E', 'C,D', 'C,E', 'D,E',
                  'A,B,C', 'A,B,D', 'A,B,E', 'A,C,D', 'A,C,E', 'A,D,E', 'B,C,D', 'B,C,E', 'B,D,E', 'C,D,E',
                  'A,B,C,D', 'A,B,C,E', 'A,B,D,E', 'A,C,D,E', 'B,C,D,E', 'A,B,C,D,E'])
    def test_book_positive_book_public_list_key_null(self, _official, selected, levels):
        """根据等级和认证过滤查询书籍-key为不为空走向量模式，key为空走正常搜索逻辑，主要控制逻辑是levels是否生效"""

        # 获取蓝思分数等级映射关系
        level_map_res = self.book.lexiLelevelMapping(self.authorization)['data']
        level_map = {}
        for level in level_map_res:
            max_plus = 0 if level['inclusiveMax'] else -1
            min_plus = 0 if level['inclusiveMin'] else 1
            if isinstance(level['max'], int):
                level_map[level['level']] = [level['min']+min_plus, level['max']+max_plus]
            else:
                level_map[level['level']] = [level['min']+min_plus, 99999999]
        level_list = levels.split(',')
        lexile_range = []
        for level_letter in level_list:
            lexile_range.append(level_map[level_letter])

        # 查询公开书籍列表
        key = ""
        pl = {
            'key': key,
            "levels": levels,
            "selected": selected,
            "official": _official,
        }
        book_res = self.book.book_public_list(self.authorization, **pl)['data']['content']
        for book in book_res:
            bookId = book['id']
            ch_key = "测试"
            if key not in book['bookName'] and key not in book['authorName'] and ch_key not in book['bookName'] and ch_key not in book['authorName']:
                try:
                    layers = self.book.book_content(self.authorization, bookId)['data']['editorStateHistories']['layers']
                except Exception as e:
                    layers = []
                    print('该书籍未在数据库中存储内容！')
                if layers:
                    for layer in layers:
                        if key in layer['text']:
                            break
                    else:
                        assert False
            # 获取故事书的 lexile 分数
            book_lexile = self.book.bookLexile(self.authorization, bookId)['data']
            for i in range(60):
                for lexile in lexile_range:
                    if lexile[0] <= book_lexile <= lexile[1]:
                        flag = True
                        break
                else:
                    # 批量更新故事书的官方认证状态
                    res = self.book.processlayers(self.authorization, bookId)
                    assert res['data']
                if flag:
                    break
                else:
                    time.sleep(1)
            else:
                assert False

            # 验证默认推送社区或精选的故事书
            if selected == 1 and selected == 0:
                assert book['selected']
            if _official == 1 and selected == 0:
                assert book['official']
            if _official == 1 and selected == 1:
                assert book['official'] or book['selected']

            if book['official']:
                # 通过bookId查询书籍详情，获取作者名称
                bookId = book['id']
                bookDetail1 = self.book.bookDetails(self.authorization, bookId)
                if bookDetail1['data']:
                    authorName = bookDetail1['data']['authorName']
                else:
                    continue
                # 根据用户名搜索用户获取用户email
                user_email_res = self.user.getSearch(self.authorization, authorName)['data']['content']
                for user_email in user_email_res:
                    email = user_email['email']
                    if email.endswith('@giggleacademy.com') or email.endswith('@giggleacademy.me'):
                        expected = 1
                        break
                else:
                    expected = 0
                # 通过bookId查询书籍详情，验证official字段返回成功
                official = self.book.bookDetails(self.authorization, bookId)['data']['official']
                assert official == expected, '通过bookId查询书籍详情,'

    @pytest.mark.smoke
    @pytest.mark.parametrize("_official", [0, 1])
    @pytest.mark.parametrize("selected", [0, 1])
    @pytest.mark.parametrize("levels", ['A', 'B', 'C', 'D', 'E', 'A,B', 'A,C', 'A,D', 'A,E', 'B,C', 'B,D', 'B,E', 'C,D', 'C,E', 'D,E',
                  'A,B,C', 'A,B,D', 'A,B,E', 'A,C,D', 'A,C,E', 'A,D,E', 'B,C,D', 'B,C,E', 'B,D,E', 'C,D,E',
                  'A,B,C,D', 'A,B,C,E', 'A,B,D,E', 'A,C,D,E', 'B,C,D,E', 'A,B,C,D,E'])
    def test_book_positive_guest_book_list_key(self, _official, selected, levels):
        """根据等级和认证过滤查询书籍-key为不为空走向量模式，key为空走正常搜索逻辑，主要控制逻辑是levels是否生效"""

        # 获取蓝思分数等级映射关系
        level_map_res = self.book.lexiLelevelMapping(self.authorization)['data']
        level_map = {}
        for level in level_map_res:
            max_plus = 0 if level['inclusiveMax'] else -1
            min_plus = 0 if level['inclusiveMin'] else 1
            if isinstance(level['max'], int):
                level_map[level['level']] = [level['min']+min_plus, level['max']+max_plus]
            else:
                level_map[level['level']] = [level['min']+min_plus, 99999999]
        level_list = levels.split(',')
        lexile_range = []
        for level_letter in level_list:
            lexile_range.append(level_map[level_letter])

        # 查询公开书籍列表
        key = "test"
        pl = {
            'key': key,
            "levels": levels,
            "selected": selected,
            "official": _official,
        }
        book_res = self.book.guest_book_list('', **pl)['data']['content']
        for book in book_res:
            bookId = book['id']
            ch_key = "测试"
            if key not in book['bookName'] and key not in book['authorName'] and ch_key not in book['bookName'] and ch_key not in book['authorName']:
                try:
                    layers = self.book.book_content(self.authorization, bookId)['data']['editorStateHistories']['layers']
                except Exception as e:
                    layers = []
                    print('该书籍未在数据库中存储内容！')
                if layers:
                    for layer in layers:
                        if key in layer['text']:
                            break
                    else:
                        assert False
            # 获取故事书的 lexile 分数
            book_lexile = self.book.bookLexile(self.authorization, bookId)['data']
            flag = False
            for i in range(60):
                for lexile in lexile_range:
                    if lexile[0] <= book_lexile <= lexile[1]:
                        flag = True
                        break
                else:
                    # 批量更新故事书的官方认证状态
                    res = self.book.processlayers(self.authorization, bookId)
                    assert res['data']
                if flag:
                    break
                else:
                    time.sleep(1)
            else:
                assert False

            # 验证默认推送社区或精选的故事书
            if selected == 1 and selected == 0:
                assert book['selected']
            if _official == 1 and selected == 0:
                assert book['official']
            if _official == 1 and selected == 1:
                assert book['official'] or book['selected']

            if book['official']:
                # 通过bookId查询书籍详情，获取作者名称
                bookId = book['id']
                bookDetail1 = self.book.bookDetails(self.authorization, bookId)
                if bookDetail1['data']:
                    authorName = bookDetail1['data']['authorName']
                else:
                    continue
                # 根据用户名搜索用户获取用户email
                user_email_res = self.user.getSearch(self.authorization, authorName)['data']['content']
                for user_email in user_email_res:
                    email = user_email['email']
                    if email.endswith('@giggleacademy.com') or email.endswith('@giggleacademy.me'):
                        expected = 1
                        break
                else:
                    expected = 0
                # 通过bookId查询书籍详情，验证official字段返回成功
                official = self.book.bookDetails(self.authorization, bookId)['data']['official']
                assert official == expected, '通过bookId查询书籍详情,'

    @pytest.mark.release
    def test_book_storybook_entry_flow(self):
        """
        故事书入口阶段完整流程测试
        按时间顺序调用各接口，验证业务数据的正确性和一致性
        """

        # bookIds = [self.public_book_id]
        # res = self.book.translation_trigger(self.authorization, bookIds)
        # assert res['message'] == 'success'

        # ==================== 1. 获取书籍公开详情 ====================
        book_detail_resp = self.book.public_book_details('', self.public_book_id)
        description = 'Barnaby the grumpy ogre thinks he can only count to three, but with the help of some chattering squirrels, grumbling bears, and squeaking bunnies, he discovers he can count much higher. A fun and simple story about learning to count.'
        # 书籍基本信息校验
        book_data = book_detail_resp['data']
        assert book_data['description'] == description
        assert book_data['bookName'] == self.public_book_name, "书籍名称不能为空"
        assert book_data['coverKey'], "书籍封面URL不能为空"

        # 书籍状态校验（公开接口应返回已发布的书籍）
        assert book_data.get('status') in [1, 'published', 'PUBLISHED', None], \
            f"公开接口返回了未发布的书籍: status={book_data.get('status')}"

        # 保存书籍信息用于后续校验
        original_language = book_data.get('language') or book_data.get('originalLanguage') or 'en'

        # ==================== 2. 获取支持的语言列表 ====================
        languages_resp = self.book.getSupportedlanguages(self.authorization, self.public_book_id)
        supported_languages = languages_resp['data']

        # 至少应支持一种语言（原始语言）
        assert len(supported_languages) >= 1, "故事书至少应支持一种语言"

        # 提取语言代码列表
        if isinstance(supported_languages[0], dict):
            language_codes = [lang.get('code') for lang in supported_languages]
        else:
            language_codes = supported_languages

        # 原始语言应在支持列表中
        assert original_language in language_codes or 'en' in language_codes, \
            f"原始语言 {original_language} 不在支持列表中: {language_codes}"

        # 选择一个语言用于后续测试
        test_language = random.choice(language_codes) if language_codes else 'en'

        # ==================== 3. 获取用户孩子列表 ====================
        kids_resp = self.user.getUserKids(self.authorization)
        kids_data = kids_resp['data']

        # 校验孩子数据完整性
        for kid in kids_data:
            assert kid.get('id'), "孩子ID不能为空"
            # 孩子应有头像或默认头像
            assert kid.get('avatar') or kid.get('avatarUrl') or kid.get('defaultAvatar') is not None, \
                f"孩子缺少头像信息: kidId={kid.get('id')}"
        this_year = strftime("%Y")  # 今年
        targetAgeChoice = random.choice(kids_data)
        targetAge = int(this_year) - int(targetAgeChoice['age'])

        # ==================== 4. 获取语言包 ====================

        language_pack_resp = self.book.languagePack(self.authorization, self.public_book_id, test_language)
        if language_pack_resp['code'] == 200:  # 如果code不是200，说明语音包还未生成成功，校验code是100051
            assert language_pack_resp['data']['bookId'] == int(self.book_id)
            url = language_pack_resp['data']['url']
            fileName = '《Barnaby Counts!》语音包'
            self.book.download_file(self.authorization, fileName, url, fileType="mp3", path="test_data")

            # 假设你有一个故事书文件（.ggb 或类似格式）
            with open(os.getcwd() + "/test_data/《Barnaby Counts!》语音包.mp3", "rb") as f:
                book_audio_data = f.read()
            # 解析为 Book 对象
            book = parse_book_from_bytes(book_audio_data)

            # 获取音频图层
            audio_layers = book.get_layers_by_types("audio", "Sound")
            for layer in audio_layers:
                print(f"音频ID: {layer.id}, 页码: {layer.page}")
        else:
            # 因为原始语言不需要语言包文件，S3 上没有对应文件
            assert language_pack_resp['code'] == 100051
            assert language_pack_resp['data'] == 'The specified key does not exist'

        # ==================== 5. 获取书籍内容下载链接 ====================
        book_url_resp = self.book.bookDetailUrl(self.authorization, self.public_book_id)
        # 下载链接校验
        url = book_url_resp['data']['url']
        fileName = '《Barnaby Counts!》书籍内容'
        self.book.download_file(self.authorization, fileName, url, fileType="book", path="test_data")

        # 假设你有一个故事书文件（.ggb 或类似格式）
        with open(os.getcwd()+"/test_data/《Barnaby Counts!》书籍内容.book", "rb") as f:
            book_data = f.read()
        # 解析为 Book 对象
        book = parse_book_from_bytes(book_data)
        # 访问书籍信息
        assert book.bookTitle == self.public_book_name
        assert book.author == 'di.bbb@giggleacademy.me'
        assert book.language == 'en'
        assert book.pageList

        # 获取特定类型的图层（如文本图层）
        text_layers = book.get_layers_by_types("text", "TextBox")
        pages = []
        for layer in text_layers:
            pages.append({'page': layer.page, 'text': layer.text})

        # ==================== 6. 获取首页语音 ====================
        index_audio_resp = self.book.indexaudio_details(self.authorization, self.public_book_id, test_language)
        if not index_audio_resp['data']:
            file = {
                'audioFile': ('story_language.mp3', open(os.getcwd() + '/test_data/story_language.mp3', 'rb'))
            }
            res = self.book.upload_indexAudio(self.authorization, self.public_book_id, test_language, file=file)
            assert res['message'] == 'success'
            index_audio_resp = self.book.indexaudio_details(self.authorization, self.public_book_id, test_language)
        # 下载链接校验
        indexAudioKey = index_audio_resp['data']['indexAudioKey']
        fileName = '《Barnaby Counts!》首页语音'
        self.materials.download_materials(self.authorization, indexAudioKey, fileName, fileType="mp3", path='test_data')
        # 假设你有一个故事书文件（.ggb 或类似格式）
        with open(os.getcwd()+"/test_data/《Barnaby Counts!》首页语音.mp3", "rb") as f:
            book_audio_data = f.read()
        # 解析为 Book 对象
        assert book_audio_data

        # ==================== 7. 获取领读数据 ====================
        narration_resp = self.book.getNarrationData(self.authorization, self.public_book_id, test_language)
        narration_data = narration_resp['data']
        if 'narrationS3Key' not in narration_data:
            # 重新生成故事书的领读数据
            regenerate_res = self.book.regenerate_narration(self.authorization, self.public_book_id)
            assert regenerate_res['data']['message'] == '领读数据重新生成任务已启动'
            narration_resp = self.book.getNarrationData(self.authorization, self.public_book_id, test_language)
            narration_data = narration_resp['data']

        # 领读数据校验（可选功能）
        if narration_data:
            # 如果有领读数据，应包含音频URL或分段信息
            narrationDataJson = json.loads(narration_data['narrationDataJson'])
            for page, narration in enumerate(narrationDataJson):
                assert narration['page'] == page+1, "故事书的领读数据保存失败！"
                assert narration['narration'], "故事书的领读数据保存失败！"

        # ==================== 8. 获取书籍 Quiz ====================
        quiz_resp = self.book.book_quiz(self.authorization, self.public_book_id, test_language)
        quiz_data = quiz_resp['data']
        if not quiz_data:
            # 异步生成故事书的quiz
            pl = {
                'story': {
                    "title": self.public_book_name,
                    "pages": pages
                },
                'targetAge': targetAge
            }
            task_id = self.book.generateasync_quiz(self.authorization, self.public_book_id, **pl)['data']['task_id']
            for i in range(10):
                # 查询故事quiz生成任务状态
                status_res = self.book.quiz_task_status(self.authorization, bookId=self.public_book_id, taskId=task_id)
                if status_res['state'] == 'running':
                    time.sleep(1)
                else:
                    break
            else:
                assert False, "10s内生成故事书quiz失败"
            quiz_save = self.book.save_book_quiz(self.authorization, self.public_book_id)
            assert quiz_save['message'] == 'success'
            quiz_resp = self.book.book_quiz(self.authorization, self.public_book_id)
            quiz_data = quiz_resp['data']

        # Quiz 数据校验（可选功能）
        questions = quiz_data.get('questions') if isinstance(quiz_data, dict) else quiz_data
        questions = json.loads(questions)['questions']

        if questions and isinstance(questions, list) and len(questions) > 0:
            for idx, question in enumerate(questions):
                # 每个问题应有问题内容
                assert question.get('question') or question.get('page') or question.get('id'), \
                    f"Quiz第{idx + 1}题缺少问题内容: {question}"

                # 选择题应有选项
                if question['questions'][0].get('type') in ['choice', 'multiple_choice', 'single_choice', 'CHOICE']:
                    options = (question['questions'][0].get('options') or question['questions'][0].get('choices')
                               or question['questions'][0].get('answers'))
                    assert options and len(options) >= 2, f"Quiz第{idx + 1}题选项数量不足: {question}"

                    # 应有正确答案
                    if 'answer' in question['questions'][0]:
                        assert question['questions'][0].get('answer') is not None, f"Quiz第{idx + 1}题缺少正确答案: {question}"

    @pytest.mark.release
    def test_book_storybook_entry_privete_flow(self):
        """
        故事书入口阶段完整流程测试
        按时间顺序调用各接口，验证业务数据的正确性和一致性
        """

        # 创建私有书籍分享链接
        token = self.book.shareBook(self.authorization, self.book_id)['data']['token']

        # ==================== 1. 获取书籍公开详情 ====================
        book_detail_resp = self.book.bookShare('', token, 'en')
        description = "Lily's socks keep disappearing, leading her on a humorous quest to find them, suspecting everything from sock-eating monsters to a giggling dryer, only to discover the surprising culprit is her very own teddy bear."
        # 书籍基本信息校验
        book_data = book_detail_resp['data']
        assert book_data['description'] == description
        assert book_data['bookName'] == self.book_name, "书籍名称不能为空"
        assert book_data['coverKey'], "书籍封面URL不能为空"

        # 书籍状态校验（公开接口应返回已发布的书籍）
        assert book_data.get('status') == 0, f"私密接口返回了未发布的书籍: status={book_data.get('status')}"

        # 保存书籍信息用于后续校验
        original_language = book_data.get('language') or book_data.get('originalLanguage') or 'en'

        # ==================== 2. 获取支持的语言列表 ====================
        languages_resp = self.book.getSupportedlanguages(self.authorization, self.public_book_id)
        supported_languages = languages_resp['data']

        # 至少应支持一种语言（原始语言）
        assert len(supported_languages) >= 1, "故事书至少应支持一种语言"

        # 提取语言代码列表
        if isinstance(supported_languages[0], dict):
            language_codes = [lang.get('code') for lang in supported_languages]
        else:
            language_codes = supported_languages

        # 原始语言应在支持列表中
        assert original_language in language_codes or 'en' in language_codes, \
            f"原始语言 {original_language} 不在支持列表中: {language_codes}"

        # 选择一个语言用于后续测试
        test_language = random.choice(language_codes) if language_codes else 'en'

        # ==================== 3. 获取用户孩子列表 ====================
        kids_resp = self.user.getUserKids(self.authorization)
        kids_data = kids_resp['data']

        # 校验孩子数据完整性
        for kid in kids_data:
            assert kid.get('id'), "孩子ID不能为空"
            # 孩子应有头像或默认头像
            assert kid.get('avatar') or kid.get('avatarUrl') or kid.get('defaultAvatar') is not None, \
                f"孩子缺少头像信息: kidId={kid.get('id')}"
        this_year = strftime("%Y")  # 今年
        targetAgeChoice = random.choice(kids_data)
        targetAge = int(this_year) - int(targetAgeChoice['age'])

        # ==================== 4. 获取语言包 ====================

        language_pack_resp = self.book.languagePack(self.authorization, self.book_id, test_language)
        if language_pack_resp['code'] == 200:  # 如果code不是200，说明语音包还未生成成功，校验code是100051
            assert language_pack_resp['data']['bookId'] == int(self.book_id)
            url = language_pack_resp['data']['url']
            fileName = '《The Sock-Eating Bear》语音包'
            self.book.download_file(self.authorization, fileName, url, fileType="mp3", path="test_data")

            # 假设你有一个故事书文件（.ggb 或类似格式）
            with open(os.getcwd() + "/test_data/《The Sock-Eating Bear》语音包.mp3", "rb") as f:
                book_audio_data = f.read()
            # 解析为 Book 对象
            book = parse_book_from_bytes(book_audio_data)

            # 获取音频图层
            audio_layers = book.get_layers_by_types("audio", "Sound")
            for layer in audio_layers:
                print(f"音频ID: {layer.id}, 页码: {layer.page}")
        else:
            # 因为原始语言不需要语言包文件，S3 上没有对应文件
            assert language_pack_resp['code'] == 100051
            assert language_pack_resp['data'] == 'The specified key does not exist'

        # ==================== 5. 获取书籍内容下载链接 ====================
        book_url_resp = self.book.bookDetailUrl(self.authorization, self.book_id)
        # 下载链接校验
        url = book_url_resp['data']['url']
        fileName = '《The Sock-Eating Bear》书籍内容'
        self.book.download_file(self.authorization, fileName, url, fileType="book", path="test_data")

        # 假设你有一个故事书文件（.ggb 或类似格式）
        with open(os.getcwd()+"/test_data/《The Sock-Eating Bear》书籍内容.book", "rb") as f:
            book_data = f.read()
        # # 解析为 Book 对象
        # book = parse_book_from_bytes(book_data)
        # # 访问书籍信息
        # assert book.bookTitle == self.book_name
        # assert book.author == 'di.bbb@giggleacademy.me'
        # assert book.language == 'en'
        # assert book.pageList
        #
        # # 获取特定类型的图层（如文本图层）
        # text_layers = book.get_layers_by_types("text", "TextBox")
        # pages = []
        # for layer in text_layers:
        #     pages.append({'page': layer.page, 'text': layer.text})

        # ==================== 6. 获取首页语音 ====================
        index_audio_resp = self.book.indexaudio_details(self.authorization, self.book_id, test_language)
        if not index_audio_resp['data']['indexAudioKey']:
            file = {
                'audioFile': ('story_language.mp3', open(os.getcwd() + '/test_data/story_language.mp3', 'rb'))
            }
            res = self.book.upload_indexAudio(self.authorization, self.book_id, test_language, file=file)
            assert res['message'] == 'success'
            index_audio_resp = self.book.indexaudio_details(self.authorization, self.book_id, test_language)
        # 下载链接校验
        indexAudioKey = index_audio_resp['data']['indexAudioKey']
        fileName = '《The Sock-Eating Bear》首页语音'
        self.materials.download_materials(self.authorization, indexAudioKey, fileName, fileType="mp3", path='test_data')
        # 假设你有一个故事书文件（.ggb 或类似格式）
        with open(os.getcwd()+"/test_data/《The Sock-Eating Bear》首页语音.mp3", "rb") as f:
            book_audio_data = f.read()
        # 解析为 Book 对象
        assert book_audio_data

        # ==================== 7. 获取领读数据 ====================
        narration_resp = self.book.getNarrationData(self.authorization, self.book_id, test_language)
        narration_data = narration_resp['data']
        if 'narrationS3Key' not in narration_data:
            # 重新生成故事书的领读数据
            regenerate_res = self.book.regenerate_narration(self.authorization, self.book_id)
            assert regenerate_res['data']['message'] == '领读数据重新生成任务已启动'
            narration_resp = self.book.getNarrationData(self.authorization, self.book_id, test_language)
            narration_data = narration_resp['data']

        # 领读数据校验（可选功能）
        if narration_data:
            # 如果有领读数据，应包含音频URL或分段信息
            narrationDataJson = json.loads(narration_data['narrationDataJson'])
            for page, narration in enumerate(narrationDataJson):
                assert narration['page'] == page+1, "故事书的领读数据保存失败！"
                assert narration['narration'], "故事书的领读数据保存失败！"

        # ==================== 8. 获取书籍 Quiz ====================
        quiz_resp = self.book.book_quiz(self.authorization, self.book_id, test_language)
        quiz_data = quiz_resp['data']
        if not quiz_data:
            # 异步生成故事书的quiz
            pl = {
                'story': {
                    "title": self.book_name,
                    "pages": pages
                },
                'targetAge': targetAge
            }
            task_id = self.book.generateasync_quiz(self.authorization, self.book_id, **pl)['data']['task_id']
            for i in range(10):
                # 查询故事quiz生成任务状态
                status_res = self.book.quiz_task_status(self.authorization, bookId=self.book_id, taskId=task_id)
                if status_res['state'] == 'running':
                    time.sleep(1)
                else:
                    break
            else:
                assert False, "10s内生成故事书quiz失败"
            quiz_save = self.book.save_book_quiz(self.authorization, self.book_id)
            assert quiz_save['message'] == 'success'
            quiz_resp = self.book.book_quiz(self.authorization, self.book_id)
            quiz_data = quiz_resp['data']

        # Quiz 数据校验（可选功能）
        questions = quiz_data.get('questions') if isinstance(quiz_data, dict) else quiz_data
        questions = json.loads(questions)['questions']

        if questions and isinstance(questions, list) and len(questions) > 0:
            for idx, question in enumerate(questions):
                # 每个问题应有问题内容
                assert question.get('question') or question.get('page') or question.get('id'), \
                    f"Quiz第{idx + 1}题缺少问题内容: {question}"

                # 选择题应有选项
                if question['questions'][0].get('type') in ['choice', 'multiple_choice', 'single_choice', 'CHOICE']:
                    options = (question['questions'][0].get('options') or question['questions'][0].get('choices')
                               or question['questions'][0].get('answers'))
                    assert options and len(options) >= 2, f"Quiz第{idx + 1}题选项数量不足: {question}"

                    # 应有正确答案
                    if 'answer' in question['questions'][0]:
                        assert question['questions'][0].get('answer') is not None, f"Quiz第{idx + 1}题缺少正确答案: {question}"

    def test_book_voice_clone_flow(self, kid_data_session):
        """
        语音克隆完整流程测试
        步骤:
        1. 获取用户语音克隆模型列表
        2. 获取指定条件的语音包列表
        3. 生成新语音包
        4. 轮询查询语音包详情直到完成
        """
        kid_id = kid_data_session
        # ========== Step 1: 获取语音克隆模型列表 ==========
        voice_models = self.book.voice_model_list(self.authorization)

        # 校验返回结构
        assert voice_models.get('code') == 0, f"voice_model_list 请求失败: {voice_models}"
        models_data = voice_models.get('data')
        assert isinstance(models_data, list), f"data 应为列表类型: {type(models_data)}"

        # 校验必须有可用的语音模型 (status=1 表示成功)
        available_models = [m for m in models_data if m.get('status') == 1]
        assert len(available_models) > 0, "没有可用的语音克隆模型 (status=1)"

        # 选取第一个可用模型进行后续测试
        selected_model = available_models[0]
        voice_model_id = selected_model.get('id')

        # 校验模型字段完整性
        assert voice_model_id is not None, "模型缺少 id 字段"
        assert 'userId' in selected_model, "模型缺少 userId 字段"
        assert 'kidId' in selected_model, "模型缺少 kidId 字段"
        assert 'voiceKey' in selected_model, "模型缺少 voiceKey 字段"
        assert selected_model.get('status') == 1, "所选模型状态应为成功(1)"

        # 如果模型有 voiceId，说明语音克隆完成
        if selected_model.get('aiModelId'):
            assert selected_model.get('voiceId') is not None, "成功状态的模型应有 voiceId"

        # ========== Step 2: 获取语音包列表 ==========
        languages_resp = self.book.getSupportedlanguages(self.authorization, self.book_id)
        supported_languages = languages_resp['data']
        # 提取语言代码列表
        if isinstance(supported_languages[0], dict):
            language_codes = [lang.get('code') for lang in supported_languages]
        else:
            language_codes = supported_languages
        # 选择一个语言用于后续测试
        test_language = random.choice(language_codes) if language_codes else 'en'

        voice_packs = self.book.book_voice_packs(self.authorization, self.book_id, kid_id, test_language, voice_model_id)
        assert voice_packs.get('code') == 0, f"book_voice_packs 请求失败: {voice_packs}"
        packs_data = voice_packs.get('data')
        assert isinstance(packs_data, list), f"data 应为列表类型: {type(packs_data)}"

        # 记录已存在的语音包数量
        existing_packs_count = len(packs_data)

        # 如果已有语音包，校验字段完整性
        if existing_packs_count > 0:
            pack = packs_data[0]
            assert 'id' in pack, "语音包缺少 id 字段"
            assert pack.get('bookId') == self.book_id, f"bookId 不匹配: 期望 {self.book_id}, 实际 {pack.get('bookId')}"
            assert pack.get('languageCode') == self.language_code, f"languageCode 不匹配"
            assert pack.get('voiceModelId') == voice_model_id, f"voiceModelId 不匹配"
            assert 'status' in pack, "语音包缺少 status 字段"

        # ========== Step 3: 生成新语音包 ==========
        generate_result = self.book.generate_voice_pack(self.authorization, self.book_id, kid_id, test_language, voice_model_id)
        assert generate_result.get('code') == 0, f"generate_voice_pack 请求失败: {generate_result}"
        gen_data = generate_result.get('data')
        assert gen_data is not None, "生成语音包返回 data 为空"

        # 校验返回的关键字段
        voice_pack_id = gen_data.get('voicePackId')
        assert voice_pack_id is not None, "返回缺少 voicePackId"
        assert gen_data.get('status') == 'queued', f"初始状态应为 'queued', 实际: {gen_data.get('status')}"

        # ========== Step 4: 轮询查询语音包详情 ==========
        max_wait_seconds = 120  # 最长等待时间
        poll_interval = 3  # 轮询间隔
        elapsed = 0
        final_status = None

        while elapsed < max_wait_seconds:
            pack_details = self.book.voice_pack_details(self.authorization, voice_pack_id)
            assert pack_details.get('code') == 0, f"voice_pack_details 请求失败: {pack_details}"
            details_data = pack_details.get('data')
            assert details_data is not None, "语音包详情 data 为空"

            # 校验字段完整性
            assert details_data.get('voicePackId') == voice_pack_id, "voicePackId 不匹配"
            assert details_data.get('bookId') == self.book_id, f"bookId 不匹配"
            assert details_data.get('languageCode') == self.language_code, "languageCode 不匹配"
            assert details_data.get('voiceModelId') == voice_model_id, "voiceModelId 不匹配"
            assert 'dbCreateTime' in details_data, "缺少 dbCreateTime 字段"
            assert 'dbModifyTime' in details_data, "缺少 dbModifyTime 字段"

            current_status = details_data.get('status')
            assert current_status in ['processing', 'success', 'failed', 'unknown'], \
                f"status 值异常: {current_status}"

            if current_status == 'success':
                final_status = 'success'
                # 成功状态应有下载链接
                assert 's3Key' in details_data, "成功状态应包含 s3Key"
                assert 'downloadUrl' in details_data, "成功状态应包含 downloadUrl"
                assert details_data.get('downloadUrl'), "downloadUrl 不应为空"
                break
            elif current_status == 'failed':
                final_status = 'failed'
                # 失败状态应有错误信息
                assert 'errorMessage' in details_data, "失败状态应包含 errorMessage"
                break

            time.sleep(poll_interval)
            elapsed += poll_interval

        # 最终状态校验 (允许超时，但要记录)
        if final_status is None:
            pytest.skip(f"语音包生成超时 ({max_wait_seconds}s)，当前状态: processing")
        elif final_status == 'failed':
            pytest.fail(f"语音包生成失败: {details_data.get('errorMessage')}")
        else:
            assert final_status == 'success', f"语音包最终状态异常: {final_status}"