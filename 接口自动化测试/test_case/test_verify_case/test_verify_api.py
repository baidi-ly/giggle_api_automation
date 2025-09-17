import pytest
import sys
import os

sys.path.append(os.getcwd())

from test_case.page_api.verify.verify_api import VerifyApi


@pytest.mark.verify
class TestVerifyApiGenerated:
    def setup_class(self):
        self.api = VerifyApi()
        self.authorization = self.api.get_authorization()


    def test_noargs_getAuditors_basic(self):
        """获取所有审核员"""
        res = self.api.getAuditors(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'


    def test_noargs_getAuditors_basic(self):
        """获取所有审核员"""
        res = self.api.getAuditors(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'


    def test_noargs_getAuditors_basic(self):
        """获取所有审核员"""
        res = self.api.getAuditors(authorization=self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'
