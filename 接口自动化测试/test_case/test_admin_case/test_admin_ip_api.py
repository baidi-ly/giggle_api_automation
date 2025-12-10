import os
import sys
import time

from test_case.page_api.admin.admin_ip_api import AdminIpApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.Admin
@pytest.mark.adminIp
class TestAdminIp:

    def setup_class(self):
        self.admin_ip = AdminIpApi()
        self.auth_admin, self.user_admin_id = self.admin_ip.get_admin_authorization()


    @pytest.mark.release
    def test_admin_ip_positive_banIp(self):
        """封禁IP-正向用例"""
        ipAddress = "172.16.31.103333"
        # 查询封禁IP列表
        ipBannedList1 = self.admin_ip.ipBannedList(self.auth_admin)['data']
        # 封禁IP
        ban_res = self.admin_ip.banIP(self.auth_admin, ipAddress)
        assert ban_res['data']['message'] == 'IP封禁成功'
        for i in range(5):
            try:
                # 查询封禁IP列表
                ipBannedList2 = self.admin_ip.ipBannedList(self.auth_admin)['data']
                assert len(ipBannedList2) - len(ipBannedList1) == 1
                assert set(ipBannedList2) - set(ipBannedList1) == {ipAddress}
                break
            except:
                time.sleep(.5)
        else:
            assert False

        # 解封IP
        unban_res = self.admin_ip.unbanIP(self.auth_admin, ipAddress)
        assert unban_res['data']['message'] == 'IP解封成功'
        # 查询封禁IP列表
        ipBannedList3 = self.admin_ip.ipBannedList(self.auth_admin)['data']
        assert ipBannedList3 == ipBannedList1

    @pytest.mark.release
    @pytest.mark.parametrize('countryCode', ['86', '1', '44', '81', '852', '886', '65', '91', '62', '82'])
    def test_admin_country_positive_banCountry(self, countryCode):
        """封禁IP - 遍历常见国家区号"""
        # 查询封禁国家区号列表
        countryBannedList1 = self.admin_ip.countryBannedList(self.auth_admin)['data']
        # 封禁的国家区号
        ban_res = self.admin_ip.banCountry(self.auth_admin, countryCode)
        assert ban_res['data']['message'] == '国家区号封禁成功'
        # 查询封禁国家区号列表
        for i in range(5):
            try:
                countryBannedLis2 = self.admin_ip.countryBannedList(self.auth_admin)['data']
                assert len(countryBannedLis2) - len(countryBannedList1) == 1
                assert set(countryBannedLis2) - set(countryBannedList1) == {countryCode}
                break
            except:
                time.sleep(.5)
        else:
            assert False

        # 解封的国家区号
        unban_res = self.admin_ip.unbanCountry(self.auth_admin, countryCode)
        assert unban_res['data']['message'] == '国家区号解封成功'
        # 查询封禁国家区号列表
        countryBannedLis3 = self.admin_ip.countryBannedList(self.auth_admin)['data']
        assert countryBannedLis3 == countryBannedList1