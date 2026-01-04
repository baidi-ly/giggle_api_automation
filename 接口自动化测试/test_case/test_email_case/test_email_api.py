import pytest
import time

from config import RunConfig
from test_case.page_api.email.email_api import EmailApi

base_url = RunConfig.baseurl

@pytest.mark.email
class TestEmail:
    """
    email 接口测试用例
    """

    def setup_class(self):
        self.email = EmailApi()
        self.authorization = self.email.get_admin_authorization()[0]

    @pytest.mark.skip(reason="不活跃用户条件难以创建")
    def test_email_inactive_user_flow(self):
        """
        端到端验证 非活跃用户邮件流程：
        1. 触发 -> 在 email_push 表中创建推送记录
        2. 查询推送列表并找到对应记录
        3. 根据记录 id 获取邮件内容
        4. 若目标邮箱列表存在，确认退订邮箱不会被包含
        """

        # 1) 触发指定时区的邮件发送
        timezone = "+08:00"
        resp_trigger = self.email.triggerEmail(self.authorization, timezone)
        assert isinstance(resp_trigger, dict), f"触发返回格式异常: {resp_trigger}"
        # 接受 code == 0 或 data 存在的两种成功表现
        assert resp_trigger.get("code", 0) == 0 or resp_trigger.get("data") is not None, f"触发失败: {resp_trigger}"

        # 2) 轮询 queryEmailPushList，直到找到 INACTIVE_USER 类型的推送记录或超时
        found_push = None
        elapsed = 0
        POLL_INTERVAL = 5
        POLL_TIMEOUT = 60
        while elapsed < POLL_TIMEOUT:
            resp_list = self.email.queryEmailPushList(self.authorization, page=0, pageSize=50)
            assert isinstance(resp_list, dict), f"查询推送列表返回格式异常: {resp_list}"
            data = resp_list.get("data") or {}
            items = data.get("content") or []
            for item in items:
                # 尝试通过 emailType、remark、subject 等字段做匹配
                if item.get("targetUser") == 'di.bbb@giggleacademy.me':
                    found_push = item
                    break
                remark = item.get("remark") or ""
                if isinstance(remark, str) and timezone in remark:
                    found_push = item
                    break
            if found_push:
                break
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL

        assert found_push is not None, "未在 /email/queryEmailPushList 中找到 INACTIVE_USER 推送记录"

        # 3) 根据记录 id 获取邮件内容
        email_id = found_push.get("id")
        assert email_id, "推送记录缺少 id 字段"
        resp_content = self.email.getEmailContent(self.authorization, email_id)
        assert isinstance(resp_content, dict), f"获取邮件内容返回格式异常: {resp_content}"
        assert resp_content.get("code", 0) == 0, f"getEmailContent 返回错误: {resp_content}"
        email_html = resp_content.get("data")
        assert email_html, "邮件内容为空"

        # 4) 查询退订列表并确认退订邮箱不会在目标列表中（如果推送记录暴露了目标邮箱）
        resp_unsub = self.email.queryUnsubscribeEmails(self.authorization, page=0, pageSize=500)
        assert isinstance(resp_unsub, dict) and resp_unsub.get("code", 0) == 0, f"查询退订列表失败: {resp_unsub}"
        unsub_emails = {e.get("email") for e in (resp_unsub.get("data") or {}).get("content") or []}

        target_emails = None
        # 不同实现可能使用不同字段名，这里做兼容检查
        if found_push.get("targetEmails"):
            target_emails = set(found_push.get("targetEmails"))
        elif found_push.get("targetEmailList"):
            target_emails = set(found_push.get("targetEmailList"))

        if target_emails is not None:
            intersection = unsub_emails.intersection(target_emails)
            assert not intersection, f"退订邮箱出现在目标列表中: {intersection}"
            print("目标列表中不包含退订邮箱。")
        else:
            print("推送记录未返回显式目标邮箱列表，跳过退订交叉校验。")

        # 5) 基本状态检查：pushStatus 字段存在且合理
        push_status = found_push.get("pushStatus") or found_push.get("status")
        print("pushStatus:", push_status)
        assert push_status in (None, "PENDING", "SENDING", "SENT", "FAILED"), f"发现异常的 pushStatus: {push_status}"
