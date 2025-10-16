import datetime
import sys
import os
from time import strftime

from test_case.page_api.book.book_api import BookApi

sys.path.append(os.getcwd())
sys.path.append("..")

import pytest

@pytest.mark.book
class TestBook:

    def setup_class(self):
        self.book = BookApi()
        self.authorization = self.book.get_authorization()
        self.now = strftime("%Y%m%d%H%M%S")

    def teardown_class(self):
        '''
        所有用例执行完之后执行，可执行动作，清理所有注册的数据
        本次测试mock只创建了注册接口，未创建清除注册用户接口，暂无代码
        '''
        pass

    @pytest.fixture(scope="class")
    def get_bookId(self):
        '''方法前置 - 创建kidId'''
        # 创建小孩账户
        bookName = '前置书籍'+self.now
        category  = 1
        seriesId = 1
        storyType = ''
        bookList = self.book.book_list(self.authorization)
        yield bookList

    @pytest.mark.parametrize("isTranslatable", [True, False], ids=[True, False])
    def test_book_translationSetting_update_normal(self, isTranslatable, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.update_translationSetting(self.authorization, bookId, isTranslatable)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == "更新成功"
        assert event_res["message"] == "success"

    def test_book_translationSetting_update_bookId_not_exist(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.update_translationSetting(self.authorization, bookId)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == 'book not found'
        assert event_res["message"] == 'book not found'


    def test_book_translationSetting_update_bookId_not_current_owner(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        pass

    def test_book_translationSetting_update_bookId_empty(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        self.book.update_translationSetting(self.authorization, '', code=403)

    def test_book_translationSetting_update_isTranslatable_wrong(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.update_translationSetting(self.authorization, bookId, '9999', code=400)
        assert event_res["data"] == "Failed to convert value of type 'java.lang.String' to required type 'boolean'; nested exception is java.lang.IllegalArgumentException: Invalid boolean value [9999]"
        assert event_res["message"] == 'invalid parameter'


    def test_book_get_translationSetting_bookId_normal(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.translationSetting(self.authorization, bookId)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"]["isTranslatable"] == False
        assert event_res["message"] == "success"

    def test_book_get_translationSetting_bookId_not_exist(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.translationSetting(self.authorization, bookId)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == 'book not found'
        assert event_res["message"] == 'book not found'

    def test_book_get_translationSetting_bookId_not_current_owner(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        pass

    def test_book_get_translationSetting_bookId_empty(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        self.book.translationSetting(self.authorization, '', code=403)


    @pytest.mark.parametrize("word, interfaceLanguage, learningLanguage, header",
                             [("hello", "en", "en", 'hello · hello'),
                              ("", "en", "en",'happy · happy'),
                              ("hello", "en", "zh", 'hello · 你好'),
                              ("hello", "zh", "en", 'hello · 你好'),   # TODO
                              ("hello", "zh", "zh", '你好 · 你好')], ids=["en_en", "default", "en_ch", "ch_en", "ch_ch"])
    def test_book_getWordDefinition_word_normal(self, word, interfaceLanguage, learningLanguage, header):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.getWordDefinition(self.authorization, word, interfaceLanguage, learningLanguage)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"]["header"] == header
        res_interfaceDefin = event_res["data"]['interfaceDefinition']
        res_learningDefin = event_res["data"]['learningDefinition']
        assert self.book.check_str_language(res_interfaceDefin) == interfaceLanguage
        assert self.book.check_str_language(res_learningDefin) == learningLanguage

    def test_book_generateVideo_bookId_normal(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.generateVideo(self.authorization, bookId)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == True
        assert event_res["message"] == "success"

    def test_book_generateVideo_bookId_not_exist(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.generateVideo(self.authorization, bookId)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == 'book not found'
        assert event_res["message"] == 'book not found'

    def test_book_generateVideo_bookId_not_current_owner(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        pass

    def test_book_generateVideo_bookId_empty(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.generateVideo(self.authorization, '', code=400)   # TODO
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: ""'''
        assert event_res["message"] == 'invalid parameter'

    def test_book_get_generateVideo_bookId_normal(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.get_generateVideos(self.authorization, bookId)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"]
        assert event_res["message"] == "success"

    def test_book_get_generateVideo_bookId_not_exist(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = -999999
        event_res = self.book.get_generateVideos(self.authorization, bookId)
        assert event_res["message"] == 'book not found'
        assert event_res['data'] == 'book not found'

    def test_book_get_generateVideo_bookId_not_current_owner(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        pass

    def test_book_get_generateVideo_bookId_empty(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.get_generateVideos(self.authorization, '', code=400)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'invalid parameter'
        assert event_res['data'] == '''Failed to convert value of type 'java.lang.String' to required type 'long'; nested exception is java.lang.NumberFormatException: For input string: ""'''

    def test_book_get_generateVideo_bookId_special_character(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.get_generateVideos(self.authorization, '@#$%^&*', code=403)

    @pytest.mark.parametrize("includeBookCover", [True, False], ids=[True, False])
    def test_book_series_list_includeBookCover_normal(self, includeBookCover, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.series_list(self.authorization, bookId, includeBookCover=includeBookCover)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == "更新成功"  # TOTEST
        assert event_res["message"] == "success"

    @pytest.mark.parametrize("includeBookCover", ["hello", 123, "!@#~"], ids=["string", "intger", "special characters"])
    def test_book_series_list_includeBookCover_wrong(self, get_bookId, includeBookCover):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.series_list(self.authorization, bookId, includeBookCover="hello")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == "更新成功"  # TOTEST
        assert event_res["message"] == "success"

    def test_book_series_list_includeBookCover_empty(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.series_list(self.authorization, bookId, includeBookCover="")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == "更新成功"  # TOTEST
        assert event_res["message"] == "success"

    def test_book_series_list_bookCoverSize_default(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.series_list(self.authorization, bookId)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == "更新成功"  # TOTEST
        assert event_res["message"] == "success"

    def test_book_series_list_bookCoverSize_negative(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.series_list(self.authorization, bookId, includeBookCount=-1)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == "更新成功"  # TOTEST
        assert event_res["message"] == "success"

    def test_book_series_list_bookCoverSize_zero(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.series_list(self.authorization, bookId, includeBookCount=0)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == "更新成功"  # TOTEST
        assert event_res["message"] == "success"

    def test_book_series_list_bookCoverSize_long(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.series_list(self.authorization, bookId, includeBookCount=99999999)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == "更新成功"  # TOTEST
        assert event_res["message"] == "success"

    def test_book_series_list_bookCoverSize_empty(self, get_bookId):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.series_list(self.authorization, bookId, includeBookCount='')
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == "更新成功"  # TOTEST
        assert event_res["message"] == "success"

    @pytest.mark.parametrize("includeBookCover", ["hello", True, "!@#~"], ids=["string", "boolen", "special characters"])
    def test_book_series_list_bookCoverSize_notInteger(self, get_bookId, includeBookCover):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        bookId = get_bookId["data"]["content"][0]["id"]
        event_res = self.book.series_list(self.authorization, bookId, includeBookCount=includeBookCover)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == "更新成功"  # TOTEST
        assert event_res["message"] == "success"

    def test_book_recommend_bookAndCourse_age_normal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        for age in range(20):
            event_res = self.book.recommend_bookAndCourse(self.authorization, age)
            assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
            assert event_res["data"]["courses"]
            assert event_res["data"]["book"]

    @pytest.mark.parametrize("age", ["hello", True, "!@#~"], ids=["string", "boolen", "special characters"])
    def test_book_recommend_bookAndCourse_age_typeWrong(self, age):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.recommend_bookAndCourse(self.authorization, age, code=400)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'invalid parameter'
        assert event_res["data"] == f'''Failed to convert value of type 'java.lang.String' to required type 'java.lang.Integer'; nested exception is java.lang.NumberFormatException: For input string: "{age}"'''

    def test_book_recommend_bookAndCourse_age_empty(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.recommend_bookAndCourse(self.authorization, '')
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"]["courses"]
        assert event_res["data"]["book"]

    def test_book_recommend_bookAndCourse_courseNum_default(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.recommend_bookAndCourse(self.authorization)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"]["courses"]
        assert event_res["data"]["book"]

    @pytest.mark.parametrize("age", ["hello", True, "!@#~"], ids=["string", "boolen", "special characters"])
    def test_book_recommend_bookAndCourse_courseNum_typeWrong(self, age):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.recommend_bookAndCourse(self.authorization, age, code=400)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'invalid parameter'
        assert event_res["data"] == f'''Failed to convert value of type 'java.lang.String' to required type 'java.lang.Integer'; nested exception is java.lang.NumberFormatException: For input string: "{age}"'''

    def test_book_recommend_bookAndCourse_courseNum_empty(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.recommend_bookAndCourse(self.authorization, '', '')
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"]["courses"]
        assert event_res["data"]["book"]

    @pytest.mark.parametrize("translateLanguage", ["en", "zh", "fr", "de", "ja", "ko", "ar"], ids=["en", "zh", "fr", "de", "ja", "ko", "ar"])
    def test_book_recommend_bookAndCourse_translateLanguage_iterate(self, translateLanguage):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据v
        event_res = self.book.recommend_bookAndCourse(self.authorization, translateLanguage=translateLanguage)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"]["courses"]
        assert event_res["data"]["book"]

    def test_book_recommend_bookAndCourse_translateLanguage_empty(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.recommend_bookAndCourse(self.authorization, translateLanguage='')
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"]["courses"]
        assert event_res["data"]["book"]

    def test_book_recommend_bookAndCourse_translateLanguage_countryNotExist(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.recommend_bookAndCourse(self.authorization, translateLanguage='eeeee')
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"]["courses"]
        assert event_res["data"]["book"]

    def test_book_recommend_get_newUserBookRules(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.recommend_newUserBookRules(self.authorization)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"]["rules"]

    def test_book_recommend_get_newUserBookRules_unauthorized(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        self.book.recommend_newUserBookRules('', code=401)

    def test_book_recommend_update_newUserBookRules_normal(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.update_recommend_newUserBookRules(self.authorization, rules="this is new rule")
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["data"] == True
        assert event_res["message"] == "success"

    def test_book_recommend_update_newUserBookRules_empty(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.update_recommend_newUserBookRules(self.authorization, code=500)
        assert "data" in event_res, f"获取孩子学习统计数据接口没有data数据，response->{event_res}"
        assert event_res["message"] == 'internal server error'

    @pytest.mark.parametrize("rules", [123, True, "!@#~"], ids=["intger", "boolen", "special characters"])
    def test_book_recommend_update_newUserBookRules_typeWrong(self, rules):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        event_res = self.book.update_recommend_newUserBookRules(self.authorization, rules=rules, code=500)
        assert event_res["message"] == 'internal server error'

    def test_book_recommend_update_newUserBookRules_withoutRules(self):
        """有效的kidId，返回完整统计数据"""
        # 获取孩子学习统计数据
        pl = {"pop_items": "rules"}
        event_res = self.book.update_recommend_newUserBookRules(self.authorization, rules="this is new rule", code=500, **pl)
        assert event_res["message"] == 'internal server error'



    def test_book_positive_upload_ok(self):
        """上传故事书语言层包到S3-正向用例"""
        res = self.book.upload(authorization=self.authorization, bookId=0, languageCode='')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('unauthorized', '未登录', 'missing'),
            ('no_auth', '空token', ''),
            ('expired_token', '鉴权异常-expired_token', 'expired_token'),
            ('invalid_token', '鉴权异常-invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_upload(self, input_param, desc, value):
        """上传故事书语言层包到S3-{desc}"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.book.upload(input_param, bookId=0, languageCode='')
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('missing', '缺失',  'missing'),
            ('empty', '为空', "''"),
            ('null', 'None', None),
        ]
    )
    def test_book_required_upload_bookId(self, input_param, desc, value):
        """上传故事书语言层包到S3-必填字段测试-{desc}(bookId)"""
        if desc == 'missing':
            pl, bookId = {'pop_items': 'bookId'}, 0
        else:
            pl, bookId = {}, value
        res = self.book.upload(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('string', '字符串', '"abc"'),
            ('float', '浮点数', 12.34),
            ('boolean', '布尔值', True),
            ('array', '数组', [1, 2, 3]),
            ('object', '对象', {'key': 'value'}),
            ('special_chars', '特殊字符', '"!@#$%^&*()"'),
            ('emoji', '表情符号', '"😀��🚀"'),
            ('long_string', '超长字符串', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
        ]
    )
    def test_book_format_upload_bookId(self, input_param, desc, value):
        """上传故事书语言层包到S3-数据格式测试-{desc}(bookId)"""
        res = self.book.upload(self.authorization, bookId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('min', '最小值', -2147483648),
            ('zero', '零值', 0),
            ('max', '最大值', 2147483647),
        ]
    )
    def test_book_boundary_upload_bookId(self, input_param, desc, value):
        """上传故事书语言层包到S3-边界值测试-{desc}(bookId)"""
        res = self.book.upload(self.authorization, bookId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    def test_book_scenario_upload_invalid_bookId(self):
        """上传故事书语言层包到S3-场景异常-无效的bookId"""
        test_params = {}
        test_params['bookId'] = 999999999
        test_params['languageCode'] = ''
        res = self.book.upload(authorization=self.authorization, **test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('missing', '缺失',  'missing'),
            ('empty', '为空', "''"),
            ('null', 'None', None),
        ]
    )
    def test_book_required_upload_languageCode(self, input_param, desc, value):
        """上传故事书语言层包到S3-必填字段测试-{desc}(languageCode)"""
        if desc == 'missing':
            pl, languageCode = {'pop_items': 'languageCode'}, 0
        else:
            pl, languageCode = {}, value
        res = self.book.upload(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('integer', '整数', 123),
            ('float', '浮点数', 12.34),
            ('boolean', '布尔值', True),
            ('array', '数组', [1, 2, 3]),
            ('object', '对象', {'key': 'value'}),
            ('special_chars', '特殊字符', '"!@#$%^&*()"'),
            ('email_format', '邮箱格式', '"test@example.com"'),
            ('phone_format', '手机号格式', '"13800138000"'),
            ('date_format', '日期格式', '"2023-12-25"'),
            ('emoji', '表情符号', '"😀🎉🚀"'),
            ('long_string', '超长字符串', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
            ('unicode', 'Unicode字符', '"中文测试"'),
            ('sql_injection', 'SQL注入', '"\'; DROP TABLE users; --"'),
            ('xss', 'XSS攻击', '"<script>alert(1)</script>"'),
            ('json_string', 'JSON字符串', '"{\\"key\\": \\"value\\"}"'),
            ('xml_string', 'XML字符串', '"<root><item>test</item></root>"'),
            ('url_string', 'URL字符串', '"https://www.example.com"'),
            ('base64_string', 'Base64字符串', '"SGVsbG8gV29ybGQ="'),
        ]
    )
    def test_book_format_upload_languageCode(self, input_param, desc, value):
        """上传故事书语言层包到S3-数据格式测试-{desc}(languageCode)"""
        res = self.book.upload(self.authorization, languageCode=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('shortest', '最短长度', ""),
            ('longest', '最长长度', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
    )
    def test_book_boundary_upload_languageCode(self, input_param, desc, value):
        """上传故事书语言层包到S3-边界值测试-{desc}(languageCode)"""
        res = self.book.upload(self.authorization, languageCode=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    def test_book_scenario_upload_invalid_languageCode(self):
        """上传故事书语言层包到S3-场景异常-无效的languageCode"""
        test_params = {}
        test_params['bookId'] = 0
        test_params['languageCode'] = 'INVALID_VALUE'
        res = self.book.upload(authorization=self.authorization, **test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.parametrize(
        'test_type,test_desc,attack_value',
        [
            ('sql_injection', 'SQL注入', "' OR 1=1 --"),
            ('xss_attack', 'XSS攻击', "<script>alert('xss')</script>"),
        ]
    )
    def test_book_security_upload_languageCode(self, test_type, test_desc, attack_value):
        """上传故事书语言层包到S3-安全测试-{test_desc}(languageCode)"""
        test_params = {}
        test_params['bookId'] = 0
        test_params['languageCode'] = attack_value
        res = self.book.upload(authorization=self.authorization, **test_params)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('missing', '缺失',  'missing'),
            ('empty', '为空', "''"),
            ('null', 'None', None),
        ]
    )
    def test_book_required_upload_file(self, input_param, desc, value):
        """上传故事书语言层包到S3-必填字段测试-{desc}(file)"""
        if desc == 'missing':
            pl, file = {'pop_items': 'file'}, 0
        else:
            pl, file = {}, value
        res = self.book.upload(authorization=self.authorization, **pl)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('integer', '整数', 123),
            ('float', '浮点数', 12.34),
            ('boolean', '布尔值', True),
            ('array', '数组', [1, 2, 3]),
            ('object', '对象', {'key': 'value'}),
            ('special_chars', '特殊字符', '"!@#$%^&*()"'),
            ('email_format', '邮箱格式', '"test@example.com"'),
            ('phone_format', '手机号格式', '"13800138000"'),
            ('date_format', '日期格式', '"2023-12-25"'),
            ('emoji', '表情符号', '"😀🎉🚀"'),
            ('long_string', '超长字符串', '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
            ('unicode', 'Unicode字符', '"中文测试"'),
            ('sql_injection', 'SQL注入', '"\'; DROP TABLE users; --"'),
            ('xss', 'XSS攻击', '"<script>alert(1)</script>"'),
            ('json_string', 'JSON字符串', '"{\\"key\\": \\"value\\"}"'),
            ('xml_string', 'XML字符串', '"<root><item>test</item></root>"'),
            ('url_string', 'URL字符串', '"https://www.example.com"'),
            ('base64_string', 'Base64字符串', '"SGVsbG8gV29ybGQ="'),
        ]
    )
    def test_book_format_upload_file(self, input_param, desc, value):
        """上传故事书语言层包到S3-数据格式测试-{desc}(file)"""
        res = self.book.upload(self.authorization, file=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('empty_file', '空文件', 'test_files/empty.txt'),
            ('small_file', '小文件', 'test_files/small.txt'),
            ('large_file', '大文件', 'test_files/large.txt'),
            ('invalid_format', '无效格式', 'test_files/invalid.exe'),
            ('max_size', '最大尺寸', 'test_files/max_size.txt'),
        ]
    )
    def test_book_boundary_upload_file(self, input_param, desc, value):
        """上传故事书语言层包到S3-边界值测试-{desc}(file)"""
        res = self.book.upload(self.authorization, file=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert 'data' in res, f'返回结果没有data数据，response->{res}'

    @pytest.mark.release
    def test_book_positive_indexaudio_details_ok(self):
        """查询故事书首页语音-正向用例"""
        res = self.book.indexaudio_details(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_indexaudio_details(self, desc, value):
        """查询故事书首页语音-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.book.indexaudio_details(value, code=200)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 400, 100006),
            ('float', 12.34, 400, 100006),
            ('boolean', True, 400, 100006),
            ('negative', -123, 400, 100006),    # todo
            ('array', [1, 2, 3], 400, 100006),
            ('object', {'key': 'value'}, 400, 100006),
            ('special_chars', '!@#$%^&*()', 404, 404),
            ('emoji', '😀🎉🚀', '', ''),
        ]
    )
    def test_book_format_indexaudio_details_bookId(self, desc, value, code, code_res):
        """查询故事书首页语音-数据格式测试(bookId)"""
        try:
            res = self.book.indexaudio_details(self.authorization, bookId=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['status'] == 404, f"接口返回状态码异常: 预期【404】，实际【{res['status']}】"
            assert res['error'] == 'Not Found', f"接口返回message信息异常: 预期【Not Found】，实际【{res['error']}】"
            # assert res['data'] == 'not found', f"接口返回data数据异常：预期【not found】，实际【{res['data']}】"
        elif code_res == 100006:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【100006】，实际【{res['code']}】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【invalid parameter】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 400),  # todo
            ('zero', 0, 200),
            ('max', 2147483647, 200),
        ]
    )
    def test_book_boundary_indexaudio_details_bookId(self, desc, value, code):
        """查询故事书首页语音-边界值测试(bookId)"""
        res = self.book.indexaudio_details(self.authorization, bookId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_book_scenario_indexaudio_details_invalid_bookId(self):
        """查询故事书首页语音-场景异常-无效的bookId"""
        bookId = 999999999
        res = self.book.indexaudio_details(self.authorization, bookId=bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('integer', 123, 200, 404),     # todo
            ('float', 12.3, 200, 404),     # todo
            ('boolean', True, 200, 404),     # todo
            ('array', [1, 2, 3], 200, 404),     # todo
            ('object', {'key': 'value'}, 200, 404),     # todo
            ('special_chars', '!@#$%^&*()', 200, 404),     # todo
            ('email_format', 'test@example.com', 200, 404),     # todo
            ('phone_format', '13800138000', 200, 404),     # todo
            ('date_format', '2023-12-25', 200, 404),     # todo
            ('emoji', '😀🎉🚀', '', ''),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 200, 404),
            ('unicode', '中文测试', '', ''),
            ('json_string', '{"key": "value"}', 200, 404),     # todo
            ('xml_string', '<root><item>test</item></root>', 404, 404),
            ('url_string', 'https://www.example.com', 403, ''),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 404),     # todo
        ]
    )
    def test_book_format_indexaudio_details_language(self, desc, value, code, code_res):
        """查询故事书首页语音-数据格式测试(language)"""
        try:
            res = self.book.indexaudio_details(self.authorization, language=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['status'] == 404, f"接口返回状态码异常: 预期【404】，实际【{res['status']}】"
            assert res['error'] == 'Not Found', f"接口返回message信息异常: 预期【{'pending'}】，实际【Not Found】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min_length', "", 404),
            ('max_length', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 404),    # todo
        ]
    )
    def test_book_boundary_indexaudio_details_language(self, desc, value, code):
        """查询故事书首页语音-边界值测试(language)"""
        res = self.book.indexaudio_details(self.authorization, language=value, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['status'] == 404, f"接口返回状态码异常: 预期【404】，实际【{res['status']}】"
        assert res['error'] == 'Not Found', f"接口返回message信息异常: 预期【{'pending'}】，实际【Not Found】"


    @pytest.mark.release
    def test_book_scenario_indexaudio_details_invalid_language(self):
        """查询故事书首页语音-场景异常-无效的language"""
        language = 'INVALID_VALUE'  # todo
        res = self.book.indexaudio_details(self.authorization, language=language)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['status'] == 404, f"接口返回状态码异常: 预期【404】，实际【{res['status']}】"
        assert res['error'] == 'Not Found', f"接口返回message信息异常: 预期【{'pending'}】，实际【Not Found】"

    @pytest.mark.release
    def test_book_positive_indexaudio_details1_ok(self, get_bookId):
        """上传并保存故事书首页语音-正向用例"""
        bookId = get_bookId["data"]["content"][0]["id"]
        file = {
            'audioFile': ('upload_test.txt', open(os.getcwd() + '/test_data/upload_test.txt', 'rb'))
        }
        res = self.book.indexaudio_details1(self.authorization, bookId, file=file)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_indexaudio_details1(self, desc, value, get_bookId):
        """上传并保存故事书首页语音-权限测试"""
        bookId = get_bookId["data"]["content"][0]["id"]
        file = {
            'audioFile': ('upload_test.txt', open(os.getcwd() + '/test_data/upload_test.txt', 'rb'))
        }
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.book.indexaudio_details1(value, bookId, file=file, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 400, 100006),
            ('float', 12.34, 400, 100006),
            ('boolean', True, 400, 100006),
            ('negative', -123, 400, 100006),    # todo
            ('array', [1, 2, 3], 400, 100006),
            ('object', {'key': 'value'}, 400, 100006),
            ('special_chars', '!@#$%^&*()', 404, 404),
            ('emoji', '😀🎉🚀', '', ''),
        ]
    )
    def test_book_format_indexaudio_details1_bookId(self, desc, value, code, code_res):
        """上传并保存故事书首页语音-数据格式测试(bookId)"""
        # bookId = get_bookId["data"]["content"][0]["id"]
        file = {
            'audioFile': ('upload_test.txt', open(os.getcwd() + '/test_data/upload_test.txt', 'rb'))
        }
        try:
            res = self.book.indexaudio_details1(self.authorization, bookId=value, file=file, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['status'] == 404, f"接口返回状态码异常: 预期【404】，实际【{res['status']}】"
            assert res['error'] == 'Not Found', f"接口返回message信息异常: 预期【Not Found】，实际【{res['error']}】"
            # assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('min', -2147483648, 400, ''),  # todo
            ('zero', 0, 200, 100045),
            ('max', 2147483647, 200, 100045),
        ]
    )
    def test_book_boundary_indexaudio_details1_bookId(self, desc, value, code, code_res):
        """上传并保存故事书首页语音-边界值测试(bookId)"""
        file = {
            'audioFile': ('upload_test.txt', open(os.getcwd() + '/test_data/upload_test.txt', 'rb'))
        }
        res = self.book.indexaudio_details1(self.authorization, bookId=value, file=file)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code_res == 100045:
            assert res['code'] == 100045, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
            assert res['message'] == 'book not found', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            assert res['data'] == 'book not found', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_book_scenario_indexaudio_details1_invalid_bookId(self):
        """上传并保存故事书首页语音-场景异常-无效的bookId"""
        bookId = 999999999
        file = {
            'audioFile': ('upload_test.txt', open(os.getcwd() + '/test_data/upload_test.txt', 'rb'))
        }
        res = self.book.indexaudio_details1(self.authorization, bookId=bookId, file=file)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 100045, f"接口返回状态码异常: 预期【100045】，实际【{res['code']}】"
        assert res['message'] == 'book not found', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'] == 'book not found', f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('integer', 123, 200, 404),     # todo
            ('float', 12.3, 200, 404),     # todo
            ('boolean', True, 200, 404),     # todo
            ('array', [1, 2, 3], 200, 404),     # todo
            ('object', {'key': 'value'}, 200, 404),     # todo
            ('special_chars', '!@#$%^&*()', 200, 404),     # todo
            ('email_format', 'test@example.com', 200, 404),     # todo
            ('phone_format', '13800138000', 200, 404),     # todo
            ('date_format', '2023-12-25', 200, 404),     # todo
            ('emoji', '😀🎉🚀', '', ''),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 200, 404),
            ('unicode', '中文测试', '', ''),
            ('json_string', '{"key": "value"}', 200, 404),     # todo
            ('xml_string', '<root><item>test</item></root>', 404, 404),
            ('url_string', 'https://www.example.com', 403, ''),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 404),     # todo
        ]
    )
    def test_book_format_indexaudio_details1_language(self, desc, value, code, code_res, get_bookId):
        """上传并保存故事书首页语音-数据格式测试(language)"""
        try:
            bookId = get_bookId["data"]["content"][0]["id"]
            file = {
                'audioFile': ('upload_test.txt', open(os.getcwd() + '/test_data/upload_test.txt', 'rb'))
            }
            res = self.book.indexaudio_details1(self.authorization, bookId, language=value, file=file, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['status'] == 404, f"接口返回状态码异常: 预期【404】，实际【{res['status']}】"
            assert res['error'] == 'Not Found', f"接口返回message信息异常: 预期【{'pending'}】，实际【Not Found】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min_length', "", 404),
            ('max_length', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 404),    # todo
        ]
    )
    def test_book_boundary_indexaudio_details1_language(self, desc, value, code, get_bookId):
        """上传并保存故事书首页语音-边界值测试(language)"""
        bookId = get_bookId["data"]["content"][0]["id"]
        file = {
            'audioFile': ('upload_test.txt', open(os.getcwd() + '/test_data/upload_test.txt', 'rb'))
        }
        res = self.book.indexaudio_details1(self.authorization, bookId, language=value, file=file, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['status'] == 404, f"接口返回状态码异常: 预期【404】，实际【{res['status']}】"
        assert res['error'] == 'Not Found', f"接口返回message信息异常: 预期【{'pending'}】，实际【Not Found】"

    @pytest.mark.release
    def test_book_scenario_indexaudio_details1_invalid_language(self, get_bookId):
        """上传并保存故事书首页语音-场景异常-无效的language"""
        language = 'INVALID_VALUE'  # todo
        bookId = get_bookId["data"]["content"][0]["id"]
        file = {
            'audioFile': ('upload_test.txt', open(os.getcwd() + '/test_data/upload_test.txt', 'rb'))
        }
        res = self.book.indexaudio_details1(self.authorization, bookId, language=language, file=file, code=404)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['status'] == 404, f"接口返回状态码异常: 预期【404】，实际【{res['status']}】"
        assert res['error'] == 'Not Found', f"接口返回message信息异常: 预期【{'pending'}】，实际【Not Found】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_book_required_indexaudio_details1_audioFile(self, desc, value, code):
        """上传并保存故事书首页语音-必填字段测试(audioFile)"""
        if desc == 'missing':
            res = self.book.indexaudio_details1(authorization=self.authorization, code=code)
        else:
            file = {
                'audioFile': (value, open(os.getcwd() + f'/test_data/{value}', 'rb'))
            }
            res = self.book.indexaudio_details1(authorization=self.authorization, file=file, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        else:
            assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
            assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
            assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('integer', 123, 200, 500),
            ('float', 12.3, 200, 500),
            ('boolean', True, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('email_format', 'test@example.com', 200, 500),
            ('phone_format', '13800138000', 200, 500),
            ('date_format', '2023-12-25', 200, 500),
            ('emoji', '😀🎉🚀', 200, 500),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 200, 500),
            ('unicode', '中文测试', 200, 500),
            ('json_string', '{"key": "value"}', 200, 500),
            ('xml_string', '<root><item>test</item></root>', 200, 500),
            ('url_string', 'https://www.example.com', 200, 500),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 500),
        ]
    )
    def test_book_format_indexaudio_details1_audioFile(self, desc, value, code, code_res):
        """上传并保存故事书首页语音-数据格式测试(audioFile)"""
        try:
            file = {
                'audioFile': (value, open(os.getcwd() + f'/test_data/{value}', 'rb'))
            }
            res = self.book.indexaudio_details1(self.authorization, file=file, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('empty', '', 500),
            ('short', 'a', 500),
            ('long', 'a' * 1000, 500),
        ]
    )
    def test_book_boundary_indexaudio_details1_audioFile(self, desc, value, code):
        """上传并保存故事书首页语音-边界值测试(audioFile)"""
        file = {
            'audioFile': (value, open(os.getcwd() + f'/test_data/{value}', 'rb'))
        }
        res = self.book.indexaudio_details1(self.authorization, file=file)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"



    @pytest.mark.release
    def test_book_positive_indexaudio_details2_ok(self):
        """上传并保存故事书首页语音-正向用例"""
        res = self.book.indexaudio_details2(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_indexaudio_details2(self, desc, value):
        """上传并保存故事书首页语音-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.book.indexaudio_details2(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 200, 500),
            ('float', 12.34, 200, 500),
            ('boolean', True, 200, 500),
            ('negative', -123, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('emoji', '😀🎉🚀', 200, 500),
        ]
    )
    def test_book_format_indexaudio_details2_bookId(self, desc, value, code, code_res):
        """上传并保存故事书首页语音-数据格式测试(bookId)"""
        try:
            res = self.book.indexaudio_details2(self.authorization, bookId=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 200),
            ('zero', 0, 200),
            ('max', 2147483647, 200),
        ]
    )
    def test_book_boundary_indexaudio_details2_bookId(self, desc, value, code):
        """上传并保存故事书首页语音-边界值测试(bookId)"""
        res = self.book.indexaudio_details2(self.authorization, bookId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_book_scenario_indexaudio_details2_invalid_bookId(self):
        """上传并保存故事书首页语音-场景异常-无效的bookId"""
        bookId = 999999999
        res = self.book.indexaudio_details2(self.authorization, bookId=bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('integer', 123, 200, 500),
            ('float', 12.3, 200, 500),
            ('boolean', True, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('email_format', 'test@example.com', 200, 500),
            ('phone_format', '13800138000', 200, 500),
            ('date_format', '2023-12-25', 200, 500),
            ('emoji', '😀🎉🚀', 200, 500),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 200, 500),
            ('unicode', 'chinese_test', 200, 500),
            ('json_string', '{"key": "value"}', 200, 500),
            ('xml_string', '<root><item>test</item></root>', 200, 500),
            ('url_string', 'https://www.example.com', 200, 500),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 500),
        ]
    )
    def test_book_format_indexaudio_details2_language(self, desc, value, code, code_res):
        """上传并保存故事书首页语音-数据格式测试(language)"""
        try:
            res = self.book.indexaudio_details2(self.authorization, language=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min_length', "", 500),
            ('max_length', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 500),
        ]
    )
    def test_book_boundary_indexaudio_details2_language(self, desc, value, code):
        """上传并保存故事书首页语音-边界值测试(language)"""
        res = self.book.indexaudio_details2(self.authorization, language=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_book_scenario_indexaudio_details2_invalid_language(self):
        """上传并保存故事书首页语音-场景异常-无效的language"""
        language = 'INVALID_VALUE'
        res = self.book.indexaudio_details2(self.authorization, language=language)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_book_required_indexaudio_details2_audioFile(self, desc, value, code):
        """上传并保存故事书首页语音-必填字段测试(audioFile)"""
        if desc == 'missing':
            res = self.book.indexaudio_details2(authorization=self.authorization, code=code)
        else:
            file = {
                'audioFile': (value, open(os.getcwd() + f'/test_data/{value}', 'rb'))
            }
            res = self.book.indexaudio_details2(authorization=self.authorization, file=file, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        else:
            assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
            assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
            assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('integer', 123, 200, 500),
            ('float', 12.3, 200, 500),
            ('boolean', True, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('email_format', 'test@example.com', 200, 500),
            ('phone_format', '13800138000', 200, 500),
            ('date_format', '2023-12-25', 200, 500),
            ('emoji', '😀🎉🚀', 200, 500),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 200, 500),
            ('unicode', 'chinese_test', 200, 500),
            ('json_string', '{"key": "value"}', 200, 500),
            ('xml_string', '<root><item>test</item></root>', 200, 500),
            ('url_string', 'https://www.example.com', 200, 500),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 500),
        ]
    )
    def test_book_format_indexaudio_details2_audioFile(self, desc, value, code, code_res):
        """上传并保存故事书首页语音-数据格式测试(audioFile)"""
        try:
            file = {
                'audioFile': (value, open(os.getcwd() + f'/test_data/{value}', 'rb'))
            }
            res = self.book.indexaudio_details2(self.authorization, file=file, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'file',
        [
            [('empty_file', '/test_files/empty.txt')],
            [('small_file', '/test_files/small.txt')],
            [('large_file', '/test_files/large.txt')],
            [('invalid_format', '/test_files/invalid.exe')],
            [('max_size', '/test_files/max_size.txt')],
        ]
    )
    def test_book_boundary_indexaudio_details2_audioFile(self, file):
        """上传并保存故事书首页语音-边界值测试(audioFile)"""
        _audioFile = []
        for i in file:
            _audioFile.append((i[0], open(os.getcwd() + i[1], 'rb')))
        file = {"audioFile": _audioFile}
        res = self.book.indexaudio_details2(self.authorization, file=file)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_book_positive_getQuiz_ok(self, get_bookId):
        """查询故事书的quiz-正向用例"""
        bookId = get_bookId["data"]["content"][0]["id"]
        res = self.book.getQuiz(self.authorization, bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        # assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_getQuiz(self, desc, value, get_bookId):
        """查询故事书的quiz-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        bookId = get_bookId["data"]["content"][0]["id"]
        res = self.book.getQuiz(value, bookId, code=200)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
            assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
            # assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 400, 100006),
            ('float', 12.34, 400, 100006),
            ('boolean', True, 400, 100006),
            ('negative', -123, 400, 100006),    # todo
            ('array', [1, 2, 3], 400, 100006),
            ('object', {'key': 'value'}, 400, 100006),
            ('special_chars', '!@#$%^&*()', 404, 404),
            ('emoji', 'test_emoji', 400, 100006),
        ]
    )
    def test_book_format_getQuiz_bookId(self, desc, value, code, code_res):
        """查询故事书的quiz-数据格式测试(bookId)"""
        try:
            res = self.book.getQuiz(self.authorization, bookId=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            if "code" in res.keys():
                assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            if "error" in res.keys():
                assert res['error'] == 'Not Found', f"接口返回message信息异常: 预期【{'pending'}】，实际【Not Found】"
            # assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"
        elif code_res == 100006:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 100006, f"接口返回状态码异常: 预期【{'pending'}】，实际【invalid parameter】"
            assert res['message'] == 'invalid parameter', f"接口返回message信息异常: 预期【{'pending'}】，实际【invalid parameter】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    def test_book_positive_quiz_ok(self, get_bookId):
        """保存故事书的quiz-正向用例"""
        bookId = get_bookId["data"]["content"][0]["id"]
        res = self.book.quiz(self.authorization, bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_quiz(self, desc, value):
        """保存故事书的quiz-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.book.quiz(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'input_param, desc, value',
        [
            ('missing', '缺失',  'missing'),
            ('empty', '为空', ""),
            ('null', 'None', None), # todo
        ]
    )
    def test_book_boundary_quiz_content(self, input_param, desc, value, get_bookId):
        """保存故事书的quiz-必填字段测试-{desc}(file)"""
        if desc == 'missing':
            pl = {'pop_items': 'questions'}
        else:
            pl = {'questions': value}
        bookId = get_bookId["data"]["content"][0]["id"]
        res = self.book.quiz(self.authorization, bookId, **pl)
        assert res == "call_error"

    @pytest.mark.release
    def test_book_positive_uploadimagebase64_ok(self):
        """上传故事书quiz图片，图片格式为base64-正向用例"""
        # file = {
        #     'imageBase64': ("upload_test.txt", open(os.getcwd() + f'/test_data/upload_test.txt', 'rb'))
        # }
        file = {'imageBase64': open(os.getcwd()+'/test_data/upload_img.png', 'rb'),'name': 'upload_img.png'}
        res = self.book.uploadimagebase64(self.authorization, file=file)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_uploadimagebase64(self, desc, value):
        """上传故事书quiz图片，图片格式为base64-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.book.uploadimagebase64(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_book_positive_generateasync_ok(self):
        """异步生成故事书的quiz-正向用例"""
        res = self.book.generateasync(self.authorization)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value',
        [
            ('unauthorized', 'missing'),
            ('no_auth', ''),
            ('expired_token', 'expired_token'),
            ('invalid_token', 'invalid_token'),
        ]
    )
    def test_book_permission_generateasync(self, desc, value):
        """异步生成故事书的quiz-权限测试"""
        # 鉴权作为位置参数直接传入（示例期望的极简风格）
        res = self.book.generateasync(value, code=401)
        if res:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 401, f"接口返回状态码异常: 预期【401】，实际【{res['code']}】"
            assert res['message'] == 'unauthorized', f"接口返回message信息异常: 预期【unauthorized】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('string', 'abc', 200, 500),
            ('float', 12.34, 200, 500),
            ('boolean', True, 200, 500),
            ('negative', -123, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
        ]
    )
    def test_book_format_generateasync_bookId(self, desc, value, code, code_res):
        """异步生成故事书的quiz-数据格式测试(bookId)"""
        try:
            res = self.book.generateasync(self.authorization, bookId=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min', -2147483648, 200),
            ('zero', 0, 200),
            ('max', 2147483647, 200),
        ]
    )
    def test_book_boundary_generateasync_bookId(self, desc, value, code):
        """异步生成故事书的quiz-边界值测试(bookId)"""
        res = self.book.generateasync(self.authorization, bookId=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_book_scenario_generateasync_invalid_bookId(self):
        """异步生成故事书的quiz-场景异常-无效的bookId"""
        bookId = 999999999
        res = self.book.generateasync(self.authorization, bookId=bookId)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('missing',  'missing', 500),
            ('empty', "", 500),
            ('null', None, 500),
        ]
    )
    def test_book_required_generateasync_content(self, desc, value, code):
        """异步生成故事书的quiz-必填字段测试(content)"""
        if desc == 'missing':
            pl = {'pop_items': 'content'}
        else:
            pl = {'content': value}
        res = self.book.generateasync(authorization=self.authorization, **pl, code=code)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        if code == 500:
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        else:
            assert res['code'] == '${pending}', f"接口返回状态码异常: 预期【{'pending'}】，实际【{res['code']}】"
            assert res['message'] == '${pending}', f"接口返回message信息异常: 预期【{'pending'}】，实际【{res['message']}】"
            assert res['data'] == '${pending}', f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('integer', 123, 200, 500),
            ('float', 12.3, 200, 500),
            ('boolean', True, 200, 500),
            ('array', [1, 2, 3], 200, 500),
            ('object', {'key': 'value'}, 200, 500),
            ('special_chars', '!@#$%^&*()', 200, 500),
            ('email_format', 'test@example.com', 200, 500),
            ('phone_format', '13800138000', 200, 500),
            ('date_format', '2023-12-25', 200, 500),
            ('emoji', 'test_emoji', 200, 500),
            ('long_string', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 200, 500),
            ('unicode', 'chinese_test', 200, 500),
            ('json_string', '{"key": "value"}', 200, 500),
            ('xml_string', '<root><item>test</item></root>', 200, 500),
            ('url_string', 'https://www.example.com', 200, 500),
            ('base64_string', 'SGVsbG8gV29ybGQ=', 200, 500),
        ]
    )
    def test_book_format_generateasync_content(self, desc, value, code, code_res):
        """异步生成故事书的quiz-数据格式测试(content)"""
        try:
            res = self.book.generateasync(self.authorization, content=value, code=code)
        except Exception as res:
            assert not code
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
            assert res['data'], f"接口返回data数据异常：预期【{'pending'}】，实际【{res['data']}】"
        elif code_res == 404:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 404, f"接口返回状态码异常: 预期【{'pending'}】，实际【404】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【{'pending'}】，实际【'not found'】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【{'pending'}】，实际【'not found'】"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code',
        [
            ('min_length', "", 500),
            ('max_length', "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 500),
        ]
    )
    def test_book_boundary_generateasync_content(self, desc, value, code):
        """异步生成故事书的quiz-边界值测试(content)"""
        res = self.book.generateasync(self.authorization, content=value)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == code, f"接口返回状态码异常: 预期【{code}】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    def test_book_scenario_generateasync_invalid_content(self):
        """异步生成故事书的quiz-场景异常-无效的content"""
        content = 'INVALID_VALUE'
        res = self.book.generateasync(self.authorization, content=content)
        assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
        assert res['code'] == 200, f"接口返回状态码异常: 预期【200】，实际【{res['code']}】"
        assert res['message'] == 'success', f"接口返回message信息异常: 预期【success】，实际【{res['message']}】"
        assert res['data'], f"接口返回data数据异常：{res['data']}"

    @pytest.mark.release
    @pytest.mark.parametrize(
        'desc, value, code, code_res',
        [
            ('sql_injection', "' OR '1'='1", 403, ''),
            ('xss_script', "<script>alert('XSS')</script>", 403, ''),
            ('xss_img', "<img src=x onerror=alert('XSS')>", 403, ''),
            ('xss_iframe', "<iframe src=javascript:alert('XSS')></iframe>", 403, ''),
            ('xml_injection', "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", 403, ''),
            ('unicode_attack', '\\x00\\x01\\x02', 200, 404),
            ('crlf_injection', 'test%0d%0aSet-Cookie: admin=true', 200, 404),
            ('code_injection', "eval('alert(1)')", 403, ''),
            ('regex_dos', '((a+)+)+$', 403, ''),
        ]
    )
    def test_book_security_generateasync_content(self, desc, value, code, code_res):
        """异步生成故事书的quiz-安全测试(content)"""
        res = self.book.generateasync(self.authorization, content=value)
        if code and not code_res:
            assert not res
        elif code_res == 500:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == 500, f"接口返回状态码异常: 预期【500】，实际【{res['code']}】"
            assert res['message'] == 'internal server error', f"接口返回message信息异常: 预期【'internal server error'】，实际【{res['message']}】"
        else:
            assert isinstance(res, dict), f'接口返回类型异常: {type(res)}'
            assert res['code'] == code_res, f"接口返回状态码异常: 预期【{code_res}】，实际【{res['code']}】"
            assert res['message'] == 'not found', f"接口返回message信息异常: 预期【'not found'】，实际【{res['message']}】"
            assert res['data'] == 'not found', f"接口返回data数据异常：预期【'not found'】，实际【{res['data']}】"

