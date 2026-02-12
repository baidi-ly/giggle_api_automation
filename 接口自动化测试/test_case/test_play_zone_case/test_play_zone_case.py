from time import strftime

import pytest

from config import RunConfig
from test_case.page_api.play_zone.play_zone_api import PlayZoneAPI

base_url = RunConfig.baseurl

class TestPlayZoneApi:
    """
    游戏乐园 接口测试用例
    """

    def setup_class(self):
        self.play_zone = PlayZoneAPI()
        self.authorization = self.play_zone.get_authorization()[0]
        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.smoke
    def test_play_zone_random_line_drawing_word(self, kid_data_session):
        """分页查询支出记录列表-正向用例"""
        kid_id = kid_data_session
        res = self.play_zone.random_line_drawing_word(self.authorization, kid_id)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"
