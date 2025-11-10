from time import strftime

import pytest


from config import RunConfig
from test_case.page_api.ai.ai_api import AiApi

base_url = RunConfig.baseurl

class TestAiApi:
    """
    ai 接口测试用例
    """

    def setup_class(self):
        self.ai = AiApi()
        self.authorization = self.ai.get_authorization()[0]
        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.smoke
    def test_ai_positive_translate_ok(self):
        """翻译文本-正向用例"""
        res = self.ai.translate(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['translatedText'] == '你好', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_ai_permission_translate(self, desc, value):
        """翻译文本-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.ai.translate(value, code=200)
        if res:
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data']['translatedText'] == '你好', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),   # todo
            ('empty', "", 500),
            ('null', None, 500),   # todo
        ]
    )
    def test_ai_required_translate_targetLanguageCode(self, desc, value, code):
        """翻译文本-必填字段测试(targetLanguageCode)"""
        if desc == 'missing':
            pl = {'pop_items': 'targetLanguageCode'}
        else:
            pl = {'targetLanguageCode': value}
        res = self.ai.translate(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【5"
            assert res['message'] == 'internal server error', f"接口返回data数据异常：预期【'internal server error'】，实际【{res['data']}】"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 200),
            ('null', None, 500),
        ]
    )
    def test_ai_required_translate_text(self, desc, value, code):
        """翻译文本-必填字段测试(text)"""
        if desc == 'missing':
            pl = {'pop_items': 'text'}
        else:
            pl = {'text': value}
        res = self.ai.translate(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        else:
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【100006】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.smoke
    def test_ai_positive_generatespeechstyleprompt_ok(self):
        """根据内容生成语音风格的prompt-正向用例"""
        res = self.ai.generatespeechstyleprompt(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data']['recommended_model'], f"接口返回data数据异常：{res['data']}"
        assert res['data']['tts_prompt'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_ai_permission_generatespeechstyleprompt(self, desc, value):
        """根据内容生成语音风格的prompt-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.ai.generatespeechstyleprompt(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 200),
            ('null', None, 500),
        ]
    )
    def test_ai_required_generatespeechstyleprompt_content(self, desc, value, code):
        """根据内容生成语音风格的prompt-必填字段测试(req)"""
        if desc == 'missing':
            pl = {'pop_items': 'content'}
        else:
            pl = {'content': value}
        res = self.ai.generatespeechstyleprompt(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        else:
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【100006】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常，实际【{res['data']}】"

    @pytest.mark.release
    def test_ai_positive_audio_ok(self):
        """给文字配音，获取音频-正向用例"""
        res = self.ai.audio(self.authorization)
