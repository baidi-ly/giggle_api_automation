import json
import time

from test_case.page_api.base_api import BaseAPI

requests = BaseAPI().http_timeout()
base_url = BaseAPI().baseurl()


class BookApi(BaseAPI):
    """书籍接口"""


    def createOrModifyBook(self, authorization, bookName, category, seriesId, storyType, DeviceType="web", **kwargs):
        """
        创建(带bookId)/修改一本书籍
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.?  2025-09-09
        # Creator: Baidi

        url = f"https://{base_url}/api/book/createOrModifyBook"
        payload = {
            "bookName": bookName,
            "category": category,
            "description": '',
            "file": "",
            "language": "zh",
            "maxAge": 10,
            "minAge": 2,
            "seriesId": seriesId,
            "storyType": storyType,
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "创建(带bookId)/修改一本书籍"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def book_list(self, authorization, searchKey="", DeviceType="web", **kwargs):
        """
        列出当前用户创建的书籍列表
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.?  2025-09-09
        # Creator: Baidi

        url = f"https://{base_url}/api/book/list"
        payload = {
            "page": 0,
            "pageSize": 10,
            "sortBy": "createTime",
            "sortDirection": "desc",
            "status": ""
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "列出当前用户创建的书籍列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def series_list(self, authorization, DeviceType="web", **kwargs):
        """
        更新故事书的翻译设置
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  ?  2025-09-08
        # Creator: Baidi
        # Update Date:  v.18.0  2025-09-08
        # updater: Baidi
        # Update Details:  1. 新增参数: `includeBookCover`, `bookCoverSize`
        url = f"https://{base_url}/api/book/series"
        payload = {
            "includeBookCover": False,
            "includeBookCount": False,
            "bookCoverSize": 3,
            "page": 0,
            "size": 10,
            "total": False,
            "translateLanguage": "en",
            "visibleOnly": True
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "更新故事书的翻译设置"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def update_translationSetting(self, authorization, bookId, isTranslatable=True, DeviceType="web", code=200):
        """
        更新故事书的翻译设置
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/book/{bookId}/translationSetting"
        payload = {
            "isTranslatable": isTranslatable
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "更新故事书的翻译设置"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if response.status_code != 403:
            response = response.json()
            return response

    def translationSetting(self, authorization, bookId, DeviceType="web", code=200):
        """
        获取故事书的翻译设置
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/book/{bookId}/translationSetting"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取故事书的翻译设置"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if code != 403:
            response = response.json()
            return response

    def getWordDefinition(self, authorization, word, interfaceLanguage, learningLanguage, DeviceType="web"):
        """
        获取故事书内单词释义
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/book/getWordDefinition"
        payload = {
            "word": word,
            "interfaceLanguage": interfaceLanguage,
            "learningLanguage": learningLanguage
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取故事书内单词释义"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def generateVideo(self, authorization, bookId, DeviceType="web", code=200):
        """
        根据故事书内容生成AI视频
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/book/generateVideo"
        payload = {
            "bookId": bookId,
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "获取故事书内单词释义"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def get_generateVideos(self, authorization, bookId, DeviceType="web", code=200):
        """
        获取故事书id获取AI视频信息
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/book/generateVideo"
        payload = {
            "bookId": bookId,
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取故事书内单词释义"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if response.status_code != 403:
            response = response.json()
            return response

    def tormsToGlossary(self, authorization, bookId, DeviceType="web"):
        """
        更新术语库
        :param bookId: 书籍id
        :return:
        """
        # Create Data:  v.18.0  2025-09-05
        # Creator: Baidi
        url = f"https://{base_url}/api/book/{bookId}/tormsToGlossary"
        payload = {
            "bookId": bookId,
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取故事书内单词释义"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def recommend_bookAndCourse(self, authorization, age=1, courseNum=3, translateLanguage="en", DeviceType="web", code=200, **kwargs):
        """
        推荐体验课与故事书
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Update Data:  v.20.0  2025-10-20
        # Creator: Baidi
        url = f"https://{base_url}/api/book/recommend/bookAndCourse"
        payload = {
            "age": age,
            "courseNum": courseNum,
            "englishLevel": 1,
            "learningPurposes": "1,3",
            "translateLanguage": translateLanguage,
            "abTest": True
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "推荐体验课与故事书"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def recommend_newUserBookRules(self, authorization, DeviceType="web", code=200):
        """
        获取新用户推荐书籍规则
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/api/book/recommend/newUserBookRules"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers)
        error_msg = "获取新用户推荐书籍规则"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        if code != 401:
            response = response.json()
            return response

    def update_recommend_newUserBookRules(self, authorization, rules='', DeviceType="web", code=200, **kwargs):
        """
        设置新用户推荐书籍规则
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-08
        # Creator: Baidi
        url = f"https://{base_url}/api/book/recommend/newUserBookRules"
        payload = {
            "rules": rules
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "设置新用户推荐书籍规则"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def termsToGlossary(self, authorization, bookId, DeviceType="web"):
        """
        设置新用户推荐书籍规则
        :param:
        :return:
        """
        # Create Data:  v.18.0  2025-09-09
        # Creator: Baidi
        url = f"https://{base_url}/api/book/{bookId}/termsToGlossary"
        timestamp = str(int(time.time() * 1000))

        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("POST", url, headers=headers)
        error_msg = "设置新用户推荐书籍规则"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def upload(self, authorization, bookId=0, languageCode='', file=None, DeviceType="web", code=200, **kwargs):
        """
        上传故事书语言层包到S3
        :param bookId: (integer, query, required) bookId
        :param languageCode: (string, query, required) languageCode
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-09-23
        url = f"https://{base_url}/api/book/languageLayers/upload"
        payload = {
            "bookId": bookId,
            "languageCode": languageCode
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload, files=file)
        error_msg = "上传故事书语言层包到S3"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def indexaudio_details(self, authorization, bookId=0, language='zh', DeviceType="web", code=200, **kwargs):
        """
        查询故事书首页语音
        :param bookId: (integer, path, required) 故事书ID
        :param language: (string, path, required) 语言代码
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-14
        url = f"https://{base_url}/api/book/{bookId}/indexAudio/{language}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        print(response.status_code)
        error_msg = "查询故事书首页语音"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            print(response)
            return response
        except json.decoder.JSONDecodeError:
            return False

    def indexaudio_details1(self, authorization, bookId=0, language='zh', file=None, DeviceType="web", code=200, **kwargs):
        """
        上传并保存故事书首页语音
        :param bookId: (integer, path, required) 故事书ID
        :param language: (string, path, required) 语言代码
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-14
        url = f"https://{base_url}/api/book/{bookId}/indexAudio/{language}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, files=file)
        error_msg = "上传并保存故事书首页语音"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def indexaudio_details2(self, authorization, bookId=0, language='zh', file=None, DeviceType="web", code=200, **kwargs):
        """
        上传并保存故事书首页语音
        :param bookId: (integer, path, required) 故事书ID
        :param language: (string, path, required) 语言代码
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-14
        url = f"https://{base_url}/api/book/{bookId}/indexAudio/{language}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, files=file)
        error_msg = "上传并保存故事书首页语音"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getQuiz(self, authorization, bookId=0, DeviceType="web", code=200, **kwargs):
        """
        查询故事书的quiz
        :param bookId: (integer, path, required) 故事书ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-16
        url = f"https://{base_url}/api/book/{bookId}/quiz"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询故事书的quiz"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def quiz(self, authorization, bookId=0, DeviceType="web", code=200, **kwargs):
        """
        保存故事书的quiz
        :param bookId: (integer, path, required) 故事书ID
        :param content: (string, body, required) 测验内容
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-16
        url = f"https://{base_url}/api/book/{bookId}/quiz"
        payload = {
            "questions": [
                {
                    "page": 0,
                    "questions": [
                        {
                            "category": "choice",
                            "type": "single-choice",
                            "title": "Where Is the Wagon Going?",
                            "question": "Where do you think the wagon is going?",
                            "answer": "To the kitchen",
                            "answerId": "1",
                            "imageTips": "",
                            "options": [
                                {
                                    "id": "1",
                                    "text": "To the kitchen",
                                    "image": "Refer to the given image style, draw the red wagon with a happy face in a cozy kitchen with a checkered floor and a wooden table, a cake on the table, soft warm colors, black outlines, digital storybook style, without any text or letters",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/c9d5ba83-33cc-4ffe-801f-82d7f4e4f2d3.jpg"
                                },
                                {
                                    "id": "2",
                                    "text": "To the park",
                                    "image": "Refer to the given image style, draw the red wagon with a happy face in a green park with trees, grass, and flowers, blue sky, soft warm colors, black outlines, digital storybook style, without any text or letters",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/556e192d-187c-44ee-82f5-8d64bef65a1e.jpg"
                                },
                                {
                                    "id": "3",
                                    "text": "To the bedroom",
                                    "image": "Refer to the given image style, draw the red wagon with a happy face in a bedroom with a soft bed and a pillow, gentle lighting, soft warm colors, black outlines, digital storybook style, without any text or letters",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/68905c79-89ab-42f1-9d3c-00b5733c53fa.jpg"
                                }
                            ],
                            "style": {
                                "questionDisplay": "voice",
                                "questionBoxStyle": "plain",
                                "optionBoxSize": "large",
                                "optionArrangement": "horizontal",
                                "optionDisplay": "image"
                            },
                            "id": "0-0",
                            "index": 0,
                            "parentId": "0"
                        }
                    ],
                    "id": "0"
                },
                {
                    "page": 1,
                    "questions": [
                        {
                            "category": "sorting",
                            "type": "dragAndDrop",
                            "question": "Sort the animals in the correct order",
                            "options": [
                                {
                                    "id": "1",
                                    "sort": 1,
                                    "text": "Elephant",
                                    "image": "A cute cartoon elephant with big ears and trunk, standing in grass, soft colors"
                                },
                                {
                                    "id": "2",
                                    "sort": 2,
                                    "text": "Lion",
                                    "image": "A friendly cartoon lion with a fluffy mane, sitting in a sunny savanna, children's book style"
                                },
                                {
                                    "id": "3",
                                    "sort": 3,
                                    "text": "Rabbit",
                                    "image": "A small cartoon rabbit with big ears, sitting in a garden, pastel colors"
                                }
                            ],
                            "imageTipsUrl": "https://static.qakjukl.net/book/quiz/images/723894162968645/acb4758044265b3ec1b58aa4e62302b5.png"
                        }
                    ]
                },
                {
                    "page": 2,
                    "questions": [
                        {
                            "category": "trueFalse",
                            "type": "trueFalse",
                            "question": "The wagon feels happy when the cake falls.",
                            "answer": False,
                            "imageTips": "",
                            "style": {
                                "questionDisplay": "text",
                                "questionBoxStyle": "plain"
                            },
                            "id": "2-0",
                            "index": 0,
                            "parentId": 2
                        }
                    ],
                    "id": 2
                },
                {
                    "page": 3,
                    "questions": [
                        {
                            "category": "choice",
                            "type": "single-choice",
                            "title": "What does the wagon carry after the cake?",
                            "question": "What does the wagon carry after the cake?",
                            "answer": "Tall stack of colorful blocks",
                            "answerId": "1",
                            "imageTips": "",
                            "options": [
                                {
                                    "id": "1",
                                    "text": "Tall stack of colorful blocks",
                                    "image": "Refer to the given image style, draw the red wagon with a friendly face carrying a tall, wobbly stack of colorful wooden blocks, in a playroom with light blue walls, fluffy white cloud decorations, and a rainbow-striped rug on the floor. The wagon is centered and smiling, blocks are stacked high and a few are leaning, teddy bears and books on shelves in the background, soft digital storybook look, warm gentle lighting, without any text or letters.",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/f867792a-fb81-40d8-8b33-22ce4b04d58b.jpg"
                                },
                                {
                                    "id": "2",
                                    "text": "Plate of cookies",
                                    "image": "Refer to the given image style, draw the red wagon with a friendly face carrying a round white plate filled with chocolate chip cookies, in a playroom with blue walls and a rainbow rug. The wagon is centered and smiling, cookies look fresh and tasty, teddy bears and toys on shelves in the background, soft digital storybook look, cozy and gentle colors, without any text or letters.",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/af106664-cf69-428a-8c2f-2c0513a4df81.jpg"
                                },
                                {
                                    "id": "3",
                                    "text": "A teddy bear",
                                    "image": "Refer to the given image style, draw the red wagon with a friendly face carrying a single brown teddy bear sitting upright, in a playroom with blue walls and a rainbow rug. The wagon is centered and smiling, the teddy bear has a cute bow around its neck, other teddy bears and books on shelves in the background, soft digital storybook look, warm gentle lighting, without any text or letters.",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/4292093b-3680-46ca-8c02-332744dec137.jpg"
                                }
                            ],
                            "style": {
                                "questionDisplay": "voice",
                                "questionBoxStyle": "plain",
                                "optionBoxSize": "large",
                                "optionArrangement": "horizontal",
                                "optionDisplay": "image"
                            },
                            "id": "3-0",
                            "index": 0,
                            "parentId": 3
                        }
                    ],
                    "id": 3
                },
                {
                    "page": 4,
                    "questions": [
                        {
                            "category": "fill-blank",
                            "type": "image-choice",
                            "title": "What happened to the blocks?",
                            "question": "The blocks _____ when the wagon hummed.",
                            "answer": "fell",
                            "answerId": "1",
                            "imageTips": "",
                            "options": [
                                {
                                    "id": "1",
                                    "text": "fell",
                                    "image": "refer the given image style, draw the red wagon from the story with a sad face, surrounded by colorful wooden blocks that have fallen and are scattered across a rainbow rug, with some blocks still toppling over, in a cozy playroom with teddy bears on shelves and blue walls with white clouds, without any text or letters",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/dfb11bce-cb55-4249-bf0c-c261804b420e.jpg"
                                },
                                {
                                    "id": "2",
                                    "text": "grew",
                                    "image": "refer the given image style, draw the red wagon from the story looking surprised, with colorful wooden blocks magically growing taller and stacking up high around it on the rainbow rug, in the same cozy playroom with teddy bears and blue walls with white clouds, without any text or letters",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/23884245-ccf4-46c6-aeb9-8fbc767b4023.jpg"
                                },
                                {
                                    "id": "3",
                                    "text": "disappeared",
                                    "image": "refer the given image style, draw the red wagon from the story with a puzzled face, sitting on the rainbow rug in the playroom, but all the colorful blocks have vanished leaving only empty space where they used to be, teddy bears and books still on the shelves, without any text or letters",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/3fe12138-2e20-4ddb-b17e-f490dfadf1a8.jpg"
                                }
                            ],
                            "style": {
                                "questionDisplay": "text",
                                "questionBoxStyle": "plain",
                                "optionBoxSize": "large",
                                "optionArrangement": "horizontal",
                                "optionDisplay": "image"
                            },
                            "id": "4-0",
                            "index": 0,
                            "parentId": 4
                        }
                    ],
                    "id": 4
                },
                {
                    "page": 5,
                    "questions": [
                        {
                            "category": "choice",
                            "type": "single-choice",
                            "title": "Who Was Sleeping?",
                            "question": "Who was sleeping on the green chair?",
                            "answer": "Orange-and-white cat",
                            "answerId": "1",
                            "imageTips": "",
                            "options": [
                                {
                                    "id": "1",
                                    "text": "Orange-and-white cat",
                                    "image": "Refer to the given image style, draw an orange-and-white cat with a blue ribbon collar curled up and sleeping peacefully on a large green armchair. The chair should have rounded arms, a soft cream blanket draped over one side, and be set in a cozy room with a stone fireplace in the background. The cat looks content and relaxed, without any text or letters.",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/d6acf905-5258-4802-bf62-577d68525236.jpg"
                                },
                                {
                                    "id": "2",
                                    "text": "Brown teddy bear",
                                    "image": "Refer to the given image style, draw a soft brown teddy bear sitting upright on the same big green armchair with a cream blanket, in a cozy room with a stone fireplace and a round window. The teddy bear should have a friendly face and a blue ribbon around its neck, without any text or letters.",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/eb9fd4a5-c7b1-4109-a06d-c63d6a357783.jpg"
                                },
                                {
                                    "id": "3",
                                    "text": "Red wagon",
                                    "image": "Refer to the given image style, draw the red wagon with a smiling face, sitting empty on the floor next to the big green armchair in a cozy room with a stone fireplace and a round window. The wagon should be clearly visible and not on the chair, without any text or letters.",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/4ce4dc2c-3cf9-4c31-ac26-b4913684a123.jpg"
                                }
                            ],
                            "style": {
                                "questionDisplay": "voice",
                                "questionBoxStyle": "plain",
                                "optionBoxSize": "large",
                                "optionArrangement": "horizontal",
                                "optionDisplay": "image"
                            },
                            "id": "5-0",
                            "index": 0,
                            "parentId": 5
                        }
                    ],
                    "id": 5
                },
                {
                    "page": 8,
                    "questions": [
                        {
                            "category": "trueFalse",
                            "type": "trueFalse",
                            "question": "At the end, does the wagon feel happy again?",
                            "answer": True,
                            "imageTips": "",
                            "style": {
                                "questionDisplay": "text",
                                "questionBoxStyle": "plain"
                            },
                            "id": "8-0",
                            "index": 0,
                            "parentId": 8
                        },
                        {
                            "category": "sorting",
                            "type": "dragAndDrop",
                            "title": "Put the Story Events in Order",
                            "question": "Put these story events in order: First, the cake falls. Next, the blocks crash. Last, the cat jumps.",
                            "imageTips": "",
                            "options": [
                                {
                                    "id": "1",
                                    "sort": 1,
                                    "text": "Cake falls",
                                    "image": "Refer to the given image style, draw the red wagon with a smiling face, a big cake with white icing and a cherry falling off a blue plate onto the floor, with a few colorful blocks nearby, all on a soft cream background, without any text or letters",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/e40e4698-2be5-4f39-bfe0-b21029eb8984.jpg"
                                },
                                {
                                    "id": "2",
                                    "sort": 2,
                                    "text": "Blocks crash",
                                    "image": "Refer to the given image style, draw the red wagon with a smiling face, colorful toy blocks scattered and tumbling across the floor, some blocks mid-air, all on a soft cream background, without any text or letters",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/e138bb47-d333-412b-995c-65626602db9e.jpg"
                                },
                                {
                                    "id": "3",
                                    "sort": 3,
                                    "text": "Cat jumps",
                                    "image": "Refer to the given image style, draw the orange-and-white cat with a blue bow leaping over the red wagon, the cat's tail up and paws outstretched, with the wagon and a few blocks below, all on a soft cream background, without any text or letters",
                                    "voice": "",
                                    "imageUrl": "https://creator.qakjukl.net/api/materials/download?key=admin/materials/676259396259909/3f4a526a-1608-4ca0-b8d9-3a58d135e2bf.jpg"
                                }
                            ],
                            "style": {
                                "questionDisplay": "text",
                                "questionBoxStyle": "plain",
                                "optionBoxSize": "large",
                                "optionArrangement": "horizontal",
                                "optionDisplay": "image"
                            },
                            "id": "8-1",
                            "index": 1,
                            "parentId": 8
                        }
                    ],
                    "id": 8
                }
            ]
        }
        payload = self.request_body(payload, **kwargs)

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        try:
            response = requests.request("POST", url, headers=headers, json=payload)
        except:
            return "call_error"
        error_msg = "保存故事书的quiz"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def uploadimagebase64(self, authorization, file=None, DeviceType="web", code=200, **kwargs):
        """
        上传故事书quiz图片，图片格式为base64
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-16
        url = f"https://{base_url}/api/book/quiz/uploadImageBase64"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        headers.update({"Content-Type":"multipart/form-data"})

        response = requests.request("POST", url, headers=headers, files=file)
        error_msg = "上传故事书quiz图片，图片格式为base64"
        # assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def generateasync(self, authorization, bookId=0, DeviceType="web", code=200, **kwargs):
        """
        异步生成故事书的quiz
        :param bookId: (integer, path, required) 故事书ID
        :param content: (string, body, required) 故事内容
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-16
        url = f"https://{base_url}/api/book/{bookId}/quiz/generateAsync"
        payload = {
            "story": {
                "title": "hq_test",
                "brief": "uu",
                "pages": [
                    {
                        "page": 0,
                        "text": "",
                        "image": "https://static.qakjukl.net/book/quiz/images/723894162968645/08ff63f1d8be9ad9738f17453e82ee63.png"
                    },
                    {
                        "page": 1,
                        "text": "",
                        "image": "https://static.qakjukl.net/book/quiz/images/723894162968645/17a21a4cfe1565f4919965925fea08c5.png"
                    },
                    {
                        "page": 2,
                        "text": "",
                        "image": "https://static.qakjukl.net/book/quiz/images/723894162968645/5fac12438ef1850fea876c10471e5c2a.png"
                    },
                    {
                        "page": 3,
                        "text": "",
                        "image": "https://static.qakjukl.net/book/quiz/images/723894162968645/be95d2e312128168a68e95a114d0d973.png"
                    },
                    {
                        "page": 4,
                        "text": "",
                        "image": "https://static.qakjukl.net/book/quiz/images/723894162968645/56853ad0e3052ddf2dc8de66454555e2.png"
                    },
                    {
                        "page": 5,
                        "text": "",
                        "image": "https://static.qakjukl.net/book/quiz/images/723894162968645/be95d2e312128168a68e95a114d0d973.png"
                    }
                ]
            },
            "targetAge": 3,
            "difficulty": 1,
            "language": "en",
            "version": "v2",
            "aspectRatio": "16:9"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "异步生成故事书的quiz"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getStatus(self, authorization, bookId=0, taskId='', DeviceType="web", code=200, **kwargs):
        """
        查询故事quiz生成任务状态
        :param bookId: (integer, path, required) 故事书ID
        :param taskId: (string, path, required) 任务ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-16
        url = f"https://{base_url}/api/book/{bookId}/quiz/{taskId}/status"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询故事quiz生成任务状态"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getReadingStatus(self, authorization, bookId=0, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        检查kid是否读过某本故事书
        :param bookId: (integer, path, required) 故事书ID
        :param kidId: (integer, query, required) 孩子ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-17
        url = f"https://{base_url}/api/book/{bookId}/reading-status"
        payload = {
            "kidId": kidId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "检查kid是否读过某本故事书"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def rating(self, authorization, bookId=0, kidId=0, DeviceType="web", code=200, **kwargs):
        """
        保存故事书评价
        :param request: (object, body, required) 评价请求
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-17
        url = f"https://{base_url}/api/book/rating"
        payload = {
            "bookId": bookId,
            "kidId": kidId,
            "rating": 3
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "保存故事书评价"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getFeedbackOptions(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取评价反馈选项配置

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-17
        url = f"https://{base_url}/api/book/rating/feedback-options"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取评价反馈选项配置"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def feedbackOptions(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        更新评价反馈选项配置
        :param optionsJson: (string, body, required) 评价选项JSON配置
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-17
        url = f"https://{base_url}/api/book/rating/feedback-options"
        payload = {
            "optionsJson": json.dumps({
                "options": [
                    {
                        "id": 1,
                        "text": "很有趣"
                    }
                ]
            })
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "更新评价反馈选项配置"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getRecommend(self, authorization, age=0, bookId=0, localTime='', recommendType='', translateLanguage='zh', DeviceType="web", code=200, **kwargs):
        """
        根据用户年龄随机推荐故事书
        :param age: (integer, query, optional) age
        :param bookId: (integer, query, optional) bookId
        :param localTime: (string, query, optional) localTime
        :param recommendType: (string, query, required) recommendType
        :param translateLanguage: (string, query, optional) translateLanguage
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-17
        url = f"https://{base_url}/api/book/recommend"
        payload = {
            "age": age,
            "bookId": bookId,
            "localTime": localTime,
            "recommendType": recommendType,
            "translateLanguage": translateLanguage
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据用户年龄随机推荐故事书"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def continueplaying(self, authorization, currentBookId=123, DeviceType="web", code=200, **kwargs):
        """
        故事书续播（Continue Playing）
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/api/book/continuePlaying"
        payload = {
            "currentBookId": currentBookId,
            "listParams": {},
            "listType": "DAILY_STORIES",
            "navigationType": "NEXT",
            "userId": 11111
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "故事书续播（Continue Playing）"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

