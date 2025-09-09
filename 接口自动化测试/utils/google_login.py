import os
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
import google.oauth2.id_token
import google.auth.transport.requests

os.environ["BROWSER"] = "chrome"
# OAuth客户端配置文件
CLIENT_SECRETS_FILE = os.getcwd() + "/../test_data/credentialss.json"
# SCOPES = ["https://www.googleapis.com/auth/userinfo.profile", "openid", "email", "profile", "https://www.googleapis.com/auth/drive.readonly"]  # openid必须包含才能拿到ID Token
SCOPES = ["https://www.googleapis.com/auth/userinfo.profile", "openid", "email", "profile"]
def get_google_id_token():
    # 创建OAuth流程
    flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
    flow.redirect_uri = 'https://creator.giggleacademy.com/'  # 修改为你自己的回调地址

    # 启动本地服务器获取用户授权
    credentials = flow.run_local_server(port=0)

    # 如果令牌过期，可以刷新令牌
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())

    # credentials.id_token 就是JWT
    id_token = credentials.id_token
    print("JWT (ID Token):", id_token)

    # 验证JWT
    request = google.auth.transport.requests.Request()
    id_info = google.oauth2.id_token.verify_oauth2_token(id_token, request, credentials.client_id)
    print("Decoded info:", id_info)

    return id_token, id_info

if __name__ == "__main__":
    get_google_id_token()
