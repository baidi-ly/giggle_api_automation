import sys
import os
from time import strftime

from test_case.page_api.admin.admin_quiz_api import AdminQuizApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.admin
@pytest.mark.adminCourse
class TestAdminQuiz:

    def setup_class(self):
        self.admin_quiz = AdminQuizApi()
        self.authorization = self.admin_quiz.get_admin_authorization()[0]
        self.now = strftime("%Y%m%d%H%M%S")

    @pytest.mark.smoke
    def test_admin_quiz_positive_getFix_ok(self):
        """题目difficulty修正-正向用例"""
        res = self.admin_quiz.questionDifficultyFix(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == True, f"接口返回data数据异常：{res['data']}"

    @pytest.fixture(scope='function')
    def create_question(self):
        """创建一条用于 TTS 的题目（测试专用），用完删除"""
        # 构造一个最小合法的 questionContent（字符串形式）
        question_content = '{"stem":"This is a TTS test question - ' + self.now + '"}'
        # 使用courseId=1作为示例，若实际环境需要调整请改成有效的courseId
        resp = self.admin_quiz.create_question(
            self.authorization,
            courseId=1,
            questionType="multiple_choice",
            questionDescription="自动化测试 TTS 题目 " + self.now,
            skill="vocabulary",
            difficulty="1",
            questionContent=question_content
        )
        assert isinstance(resp, dict), f"create_question 返回类型异常: {type(resp)}"
        assert 'data' in resp, f"create_question 返回没有 data: {resp}"
        created = resp['data']
        question_id = created.get('id') if isinstance(created, dict) else None
        assert question_id is not None, f"创建题目失败，resp->{resp}"

        yield question_id

        # 清理：删除题目
        del_resp = self.admin_quiz.delete_question(self.authorization, question_id)
        assert isinstance(del_resp, dict), f"delete_question 返回类型异常: {type(del_resp)}"

    @pytest.marke.release
    def test_quiz_generate_tts_and_check_status(self, create_question):
        """场景：创建题目 -> 提交到TTS队列 -> 检查队列状态"""
        question_id = create_question

        # 1) 提交到 TTS 队列
        gen_resp = self.admin_quiz.generate_tts(self.authorization, [question_id])
        assert isinstance(gen_resp, dict), f"generate_tts 返回类型异常: {type(gen_resp)}"
        assert gen_resp.get('code') == 200, f"generate_tts 接口返回异常: {gen_resp}"
        assert 'data' in gen_resp, f"generate_tts 返回没有 data: {gen_resp}"
        added_count = gen_resp['data'].get('addedCount')
        assert isinstance(added_count, int) and added_count >= 1, f"addedCount 非法: {gen_resp}"

        # 2) 获取队列状态，至少应返回 queueSize 字段（为数字）
        status_resp = self.admin_quiz.get_tts_status(self.authorization)
        assert isinstance(status_resp, dict), f"get_tts_status 返回类型异常: {type(status_resp)}"
        assert status_resp.get('code') == 200, f"get_tts_status 接口返回异常: {status_resp}"
        assert 'data' in status_resp, f"get_tts_status 返回没有 data: {status_resp}"
        queue_size = status_resp['data'].get('queueSize')
        assert isinstance(queue_size, int), f"queueSize 类型异常: {type(queue_size)}, resp: {status_resp}"

        # 3) 进一步断言：queueSize 应该 >= 0，且在刚刚添加后通常 >=1（环境异步处理时可能快速消费）
        assert queue_size >= 0