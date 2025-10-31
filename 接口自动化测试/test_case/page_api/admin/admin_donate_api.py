
import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().admin_baseurl()


class AdminDonateApi(BaseAPI):
    """捐赠后台接口"""

    def getList(self, authorization, page=0, size=20, DeviceType="web", code=200, **kwargs):
        """
        分页查询支出记录列表
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-17
        url = f"https://{base_url}/admin/donate/expend/list"
        payload = {
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "分页查询支出记录列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def updateRemark(self, authorization, category='test1', detailUrl='https://baidu.com', remark='', id=0, DeviceType="web", code=200, **kwargs):
        """
        更新支出记录的备注、详情URL和分类
        :param category: (string, query, optional) 分类
        :param detailUrl: (string, query, optional) 详情URL
        :param remark: (string, query, optional) 备注
        :param transactionId: (string, query, required) 交易ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-20
        url = f"https://{base_url}/admin/donate/expend/update-remark"
        payload = {
            "category": category,
            "detailUrl": detailUrl,
            "remark": remark,
            "id": id
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