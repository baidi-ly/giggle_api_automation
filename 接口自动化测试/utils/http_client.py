import requests
import json
import time
import uuid
import hashlib
import base64
import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.config import Config
from utils.logger import logger

# 尝试导入配置管理器
try:
    from config_manager import config_manager
    USE_CONFIG_MANAGER = True
except ImportError:
    USE_CONFIG_MANAGER = False

class HttpClient:
    def __init__(self):
        """初始化HTTP客户端"""
        self.session = requests.Session()
        
        # 设置基本请求头
        self.session.headers.update(Config.DEFAULT_HEADERS)
        
        # 添加自定义请求头 - 设备类型、设备ID等
        self.session.headers.update({
            "DeviceType": "web",
        })
        
        # 获取token
        self._auth_token = None
        
        # 生成设备ID
        self._device_id = str(uuid.uuid4())
    
    @property
    def base_url(self):
        """动态获取base_url，确保使用最新配置"""
        if USE_CONFIG_MANAGER:
            return config_manager.get('BASE_URL', Config.BASE_URL)
        else:
            return Config.BASE_URL
    
    def _generate_auth_token(self, timestamp, device_id):
        """生成AuthToken"""
        key = f"{timestamp}{device_id}{Config.AUTH_KEY}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def _encode_password(self, password):
        """对密码进行base64编码"""
        # 确保密码是字符串类型，保持原始格式
        if isinstance(password, float):
            # 如果是浮点数，保持原始格式（如123456.0）
            password_str = str(password)
        else:
            password_str = str(password)
        return base64.b64encode(password_str.encode('utf-8')).decode('utf-8')
    
    def _set_auth_token(self, token):
        """设置认证token"""
        self._auth_token = token
        # 不使用Bearer前缀，直接使用token
        self.session.headers.update({"Authorization": token})
        
    def _update_headers(self):
        """更新请求头"""
        # 使用固定的设备ID
        device_id = self._device_id
        # 生成时间戳
        timestamp = str(int(time.time() * 1000))
        # 生成认证token
        auth_token = self._generate_auth_token(timestamp, device_id)
        
        # 更新请求头
        self.session.headers.update({
            "AuthToken": auth_token,
            "DeviceId": device_id,
            "Timestamp": timestamp
        })
        
        # 确保Content-Type和DeviceType头存在
        if "Content-Type" not in self.session.headers:
            self.session.headers["Content-Type"] = "application/json"
        if "DeviceType" not in self.session.headers:
            self.session.headers["DeviceType"] = "web"
    
    def request(self, method, url, **kwargs):
        """发送HTTP请求"""
        full_url = f"{self.base_url}{url}"
        self._update_headers()
        
        # 如果请求中包含密码，进行编码（登录接口除外）
        if 'json' in kwargs and 'password' in kwargs['json'] and url != "/api/user/login":
            kwargs['json']['password'] = self._encode_password(kwargs['json']['password'])
        
        # 记录请求信息
        logger.info(f"发送{method}请求到: {full_url}")
        logger.info(f"请求头: {self.session.headers}")
        if 'json' in kwargs:
            logger.info(f"请求体: {json.dumps(kwargs['json'], ensure_ascii=False)}")
        
        try:
            response = self.session.request(
                method=method,
                url=full_url,
                **kwargs  # 不传递headers参数，让session自动处理
            )
            
            # 记录响应信息
            logger.info(f"响应状态码: {response.status_code}")
            logger.info(f"响应内容: {response.text}")
            
            return response
        except Exception as e:
            logger.error(f"请求失败: {str(e)}")
            raise
    
    def get(self, url, **kwargs):
        """发送GET请求"""
        return self.request('GET', url, **kwargs)
    
    def post(self, url, **kwargs):
        """发送POST请求"""
        response = self.request("POST", url, **kwargs)
        
        # 如果是登录请求，并且登录成功，自动设置token
        if url == "/api/user/login" and response.status_code == 200:
            try:
                resp_data = response.json()
                # 确保响应码是200，并且data不为None
                if resp_data.get('code') == 200 and resp_data.get('data') is not None and 'token' in resp_data['data']:
                    token = resp_data['data']['token']
                    self._set_auth_token(token)
                    logger.info(f"自动设置认证token: {token}")
                elif resp_data.get('code') != 200:
                    logger.error(f"登录失败，业务状态码: {resp_data.get('code')}, 消息: {resp_data.get('message')}")
            except Exception as e:
                logger.error(f"处理登录响应时出错: {str(e)}")
        
        return response
    
    def put(self, url, **kwargs):
        """发送PUT请求"""
        return self.request('PUT', url, **kwargs)
    
    def delete(self, url, **kwargs):
        """发送DELETE请求"""
        return self.request('DELETE', url, **kwargs) 