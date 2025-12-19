
import pytest
import sys
import os

import config
from test_case.page_api.base_api import BaseAPI
from test_case.page_api.book.book_api import BookApi
from test_case.page_api.common.common_api import CommonApi
from test_case.page_api.materials.materials_api import MaterialsApi

sys.path.append(os.getcwd())
sys.path.append("..")

base_url = BaseAPI().baseurl()
expired_token = config.RunConfig.expired_token


@pytest.mark.common
class TestCommon:

    def setup_class(self):
        self.common = CommonApi()
        self.book = BookApi()
        self.materials = MaterialsApi()
        self.authorization = self.common.get_authorization()[0]

    @pytest.mark.smoke
    def test_common_positive_Getfileurl_coverKey_ok(self):
        """根据url获取文件的下载链接-coverKey"""
        books_res = self.book.book_list(self.authorization)['data']['content']
        for book in books_res:
            if book['bookName'] == 'The Sock-Eating Bear':
                coverKey = book['coverKey']
                break
        res = self.common.Getfileurl(self.authorization, coverKey)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
        assert res['data']['url'] == 'https://static' + base_url.replace('creator', '') + '/'+ coverKey
        url = res['data']['url']
        fileName = coverKey.split('/')[-1].split('.')[0]
        self.materials.download_materials(self.authorization, '', fileName, fileType="png", url=url)

    @pytest.mark.smoke
    def test_common_positive_Getfileurl_bookKey_ok(self):
        """根据url获取文件的下载链接-bookKey"""
        books_res = self.book.book_list(self.authorization, pageSize=10)['data']['content']
        for book in books_res:
            if book['bookName'] == 'The Sock-Eating Bear':
                bookKey = book['bookKey']
                break
        res = self.common.Getfileurl(self.authorization, bookKey)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
        assert res['data']['url'] == 'https://static' + base_url.replace('creator', '') + '/'+ bookKey
        url = res['data']['url']
        fileName = bookKey.split('/')[-1].split('.')[0]
        self.materials.download_materials(self.authorization, '', fileName, fileType="book", url=url)

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', expired_token),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_common_permission_Getfileurl(self, desc, value):
        """根据url获取文件的下载链接-权限测试-公开接口"""
        books_res = self.book.book_list(self.authorization)['data']['content']
        for book in books_res:
            if book['bookName'] == 'The Sock-Eating Bear':
                coverKey = book['coverKey']
                break
        res = self.common.Getfileurl(value, coverKey)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
        assert res['data']['url'] == 'https://static' + base_url.replace('creator', '') + '/'+ coverKey