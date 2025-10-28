
import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().admin_baseurl()


class AdminDonateApi(BaseAPI):
    """捐赠接口"""

    def updateRemark(self, authorization, category='test1', detailUrl='https://baidu.com', remark='', transactionId='0xd3563ddfd3849b81d68216287a0263aaea6b6b8afb2be53cb72a319fad83e3d2', DeviceType="web", code=200, **kwargs):
        """
        更新支出记录的备注、详情URL和分类
        :param category: (string, query, optional) 分类
        :param detailUrl: (string, query, optional) 详情URL
        :param remark: (string, query, optional) 备注
        :param transactionId: (string, query, required) 交易ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-20
        url = f"https://{base_url}/api/donate/expend/update-remark"
        payload = {
            "category": category,
            "detailUrl": detailUrl,
            "remark": remark,
            "transactionId": transactionId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "更新支出记录的备注、详情URL和分类"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False