import unittest
import requests

class TestSQLInjection(unittest.TestCase):
    '''模拟 SQL 注入攻击的情况。通过向接口发送恶意的 SQL 注入数据，验证系统是否能防止 SQL 注入。'''
    def setUp(self):
        self.base_url = 'http://example.com/api/user'  # 替换为你的 API 接口

    def test_sql_injection(self):
        # 模拟 SQL 注入攻击，输入恶意 SQL 字符串
        payload = {
            "user_id": "1 OR 1=1 --"  # SQL 注入攻击负载
        }
        response = requests.get(self.base_url, params=payload)

        # 验证返回的结果不应该泄漏数据库错误信息
        self.assertNotIn("SQL syntax", response.text)  # 如果返回了 SQL 错误信息，说明未防护
        self.assertEqual(response.status_code, 200)  # 如果状态码为 200，表示没有出现异常

import unittest
import requests

class TestXSS(unittest.TestCase):
    '''XSS 攻击通过注入恶意的 JavaScript 代码来执行脚本，通常是通过 HTTP 请求传递的用户输入。我们需要验证接口是否能够有效过滤或转义这些恶意的脚本。'''
    def setUp(self):
        self.base_url = 'http://example.com/api/comment'  # 替换为你的 API 接口

    def test_xss_protection(self):
        # 模拟 XSS 攻击，发送含有恶意脚本的请求
        payload = {
            "comment": "<script>alert('Hacked!');</script>"  # XSS 脚本注入
        }
        response = requests.post(self.base_url, data=payload)

        # 验证响应中没有包含恶意脚本，且应显示转义后的文本
        self.assertNotIn("<script>", response.text)  # 返回内容不应包含 <script>
        self.assertNotIn("alert('Hacked!');", response.text)  # 不应执行脚本
        self.assertEqual(response.status_code, 200)  # 状态码应为 200

import unittest
import requests

class TestCSRFProtection(unittest.TestCase):
    '''CSRF 攻击是通过伪造请求来进行的，通常攻击者会诱使已认证的用户在不知情的情况下向 Web 应用发送请求。防止 CSRF 攻击的一种方法是使用 CSRF token。'''
    def setUp(self):
        self.base_url = 'http://example.com/api/update-profile'  # 替换为你的 API 接口
        self.session = requests.Session()  # 使用 Session 来保持会话

    def test_csrf_protection(self):
        # 1. 用户登录并获取 CSRF token
        login_data = {
            'username': 'test_user',
            'password': 'password123'
        }
        response = self.session.post('http://example.com/api/login', data=login_data)
        csrf_token = response.cookies.get('csrf_token')  # 假设 CSRF token 存储在 cookie 中

        # 2. 模拟恶意请求，不带 CSRF token
        payload = {
            "username": "attacker_user",
            "email": "attacker@example.com"
        }
        headers = {
            'X-CSRF-TOKEN': ''  # 恶意请求，不带 CSRF token
        }
        response = self.session.post(self.base_url, data=payload, headers=headers)

        # 3. 验证接口拒绝了 CSRF 攻击
        self.assertEqual(response.status_code, 403)  # 防止 CSRF 的请求应该返回 403 Forbidden

        # 4. 正常的请求，带上有效的 CSRF token
        headers['X-CSRF-TOKEN'] = csrf_token
        response = self.session.post(self.base_url, data=payload, headers=headers)

        self.assertEqual(response.status_code, 200)  # 正常请求应返回 200 OK

if __name__ == '__main__':
    unittest.main()

