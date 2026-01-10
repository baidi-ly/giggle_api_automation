import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
admin_base_url = BaseAPI().admin_baseurl()


class AdminGroupQrCodeApi(BaseAPI):
    """进群二维码管理接口"""

    def create_group_qr_code(self, authorization, createGroupQrCodeReq, DeviceType="web"):
        """
        新增进群二维码配置
        :param authorization: 用户认证令牌
        :param createGroupQrCodeReq: (object, body, required) CreateGroupQrCodeReq请求体
        :param DeviceType: 设备类型，默认为web
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  v1.24.0  2025-01-10
        # Creator: 进群二维码管理接口封装
        url = f"https://{admin_base_url}/admin/group-qr-code/create"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=createGroupQrCodeReq)
        error_msg = "新增进群二维码配置"
        if response.status_code != 200:
            try:
                return response.json()
            except:
                return {"code": response.status_code, "message": response.text, "data": response.text}
        return response.json()

    def update_group_qr_code(self, authorization, updateGroupQrCodeReq, DeviceType="web"):
        """
        修改进群二维码配置
        :param authorization: 用户认证令牌
        :param updateGroupQrCodeReq: (object, body, required) UpdateGroupQrCodeReq请求体
        :param DeviceType: 设备类型，默认为web
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  v1.24.0  2025-01-10
        # Creator: 进群二维码管理接口封装
        url = f"https://{admin_base_url}/admin/group-qr-code/update"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=updateGroupQrCodeReq)
        error_msg = "修改进群二维码配置"
        if response.status_code != 200:
            try:
                return response.json()
            except:
                return {"code": response.status_code, "message": response.text, "data": response.text}
        return response.json()

    def delete_group_qr_code(self, authorization, id, DeviceType="web"):
        """
        删除进群二维码配置
        :param authorization: 用户认证令牌
        :param id: (integer, path, required) 配置ID
        :param DeviceType: 设备类型，默认为web
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  v1.24.0  2025-01-10
        # Creator: 进群二维码管理接口封装
        url = f"https://{admin_base_url}/admin/group-qr-code/delete/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除进群二维码配置"
        if response.status_code != 200:
            try:
                return response.json()
            except:
                return {"code": response.status_code, "message": response.text, "data": response.text}
        return response.json()

    def update_group_qr_code_status(self, authorization, updateGroupQrCodeStatusReq, DeviceType="web"):
        """
        设置进群二维码配置状态
        :param authorization: 用户认证令牌
        :param updateGroupQrCodeStatusReq: (object, body, required) UpdateGroupQrCodeStatusReq请求体
        :param DeviceType: 设备类型，默认为web
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  v1.24.0  2025-01-10
        # Creator: 进群二维码管理接口封装
        url = f"https://{admin_base_url}/admin/group-qr-code/status"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=updateGroupQrCodeStatusReq)
        error_msg = "设置进群二维码配置状态"
        if response.status_code != 200:
            try:
                return response.json()
            except:
                return {"code": response.status_code, "message": response.text, "data": response.text}
        return response.json()

    def get_group_qr_code_list(self, authorization, countryCode=None, channel=None, status=None, DeviceType="web"):
        """
        查询进群二维码配置列表
        :param authorization: 用户认证令牌
        :param countryCode: (string, query, optional) 国家代码
        :param channel: (string, query, optional) 渠道
        :param status: (integer, query, optional) 状态
        :param DeviceType: 设备类型，默认为web
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  v1.24.0  2025-01-10
        # Creator: 进群二维码管理接口封装
        url = f"https://{admin_base_url}/admin/group-qr-code/list"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        params = {}
        if countryCode is not None:
            params["countryCode"] = countryCode
        if channel is not None:
            params["channel"] = channel
        if status is not None:
            params["status"] = status
        response = requests.request("GET", url, headers=headers, params=params)
        error_msg = "查询进群二维码配置列表"
        if response.status_code != 200:
            try:
                return response.json()
            except:
                return {"code": response.status_code, "message": response.text, "data": response.text}
        return response.json()
