import json
import os
import time

from config import RunConfig
from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()
AUTH_KEY = RunConfig.AUTH_KEY


class AiApi(BaseAPI):
    """AI相关接口"""

    def translate(self, authorization, targetLanguageCode='zh', text='hello', DeviceType="web", code=200, **kwargs):
        """
        翻译文本
        :param targetLanguageCode: (string, query, required) 目标语言代码
        :param text: (string, query, required) 要翻译的文本
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-20
        url = f"https://{base_url}/api/ai/translate"
        payload = {
            "targetLanguageCode": targetLanguageCode,
            "text": text
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "翻译文本"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def generatespeechstyleprompt(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        根据内容生成语音风格的prompt
        :param content: (object, body, required) content
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-22
        url = f"https://{base_url}/api/ai/generateSpeechStylePrompt"
        payload = {
          "content": "Once upon a time, there was a brave little mouse who lived in a cozy hole..."
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "根据内容生成语音风格的prompt"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def audio(self, authorization, enableCache=False, DeviceType="web", code=200, **kwargs):
        """
        给文字配音，获取音频
        :param req: (object, body, required) req
        :param enableCache: (boolean, query, optional) enableCache
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-10
        url = f"https://{base_url}/api/ai/speech/audio"
        payload1 = {
            "enableCache": enableCache
        }
        payload2 = {
            "lang": "en-US",
            "voiceName": "en-US-AvaNeural",
            "content": "Hello, welcome to Giggle Academy!",
            "prompt": "cheerful, medium tempo"
        }
        payload2 = self.request_body(payload2, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload1, json=payload2)
        error_msg = "给文字配音，获取音频"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            # 保存成 mp3
            path = os.getcwd() + "/test_data/speech_1.mp3"
            with open(path, "wb") as f:
                f.write(response.content)
            print("音频已保存到 speech.mp3")
        except requests.HTTPError as err:
            print("调用失败:", err.response.status_code, err.response.text)
        except requests.RequestException as err:
            print("网络/其他异常:", err)

