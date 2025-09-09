
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class GameApi(BaseAPI):
    """游戏接口"""

    def __init__(self):
        '''有一个基础登录用户用于常规操作，当需要切换到其他用户时，调用接口传入该用户的bearerToken'''
        self.authorization = self.get_authorization()


    def search_game(self, authorization, key, DeviceType="web", **kwargs):
        """
        搜索游戏
        :param key: 搜索关键词，必填，不能为空
        :param inviteByCode: 设备类型
        :param kwargs: 可从kwargs中获取size，可选，默认10，最⼤100
        :return:
        """
        # Create Data:  创建基线，创建时间
        # Creator: 接口作者
        # Update Date:  修改基线，修改时间
        # updater: 接口维护人员
        # Update Details:  接口维护详情
        url = "https://{0}/api/game/search".format(base_url)
        payload = {
            "key": key,
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "搜索游戏"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

