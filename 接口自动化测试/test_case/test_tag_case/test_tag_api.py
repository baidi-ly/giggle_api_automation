import sys
import os
from time import strftime

from test_case.page_api.tag.tag_api import TagApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.tag
class TestTag:

    def setup_class(self):
        self.tag = TagApi()
        self.authorization = self.tag.get_authorization()[0]
        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.release
    def test_tag_positive_popular_tags_ok(self):
        """获取当前被引用的最多的12个标签-正向用例"""
        res = self.tag.popular_tags(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert len(res['data']) == 12, f"接口返回data标签数据异常：{res['data']}"

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
    def test_tag_permission_popular_tags(self, desc, value):
        """获取当前被引用的最多的12个标签-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.tag.popular_tags(value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert len(res['data']) == 12, f"接口返回data标签数据异常：{res['data']}"

