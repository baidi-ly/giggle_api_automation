import json
import time

from pandas import DataFrame

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
            "pageSize": 100,
            "sortBy": "createTime",
            "sortDirection": "desc",
            "status": "",
            "searchKey": searchKey
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
        查询故事书系列列表
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
            "kidId": '',
            "includeBookCover": False,
            "includeBookCount": False,
            "bookCoverSize": 3,
            "page": 0,
            "size": 100,
            "total": False,
            "translateLanguage": "",
            "visibleOnly": True
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)
        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询故事书系列列表"
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

    def languageLayers_upload(self, authorization, bookId=0, languageCode='', file=None, DeviceType="web", code=200, **kwargs):
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

    def upload_indexAudio(self, authorization, bookId=0, language='zh', file=None, DeviceType="web", code=200, **kwargs):
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
        error_msg = "	上传并保存故事书首页语音"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def book_quiz(self, authorization, bookId=0, DeviceType="web", code=200):
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

    def save_book_quiz(self, authorization, bookId=0, DeviceType="web", code=200, **kwargs):
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
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def generateasync_quiz(self, authorization, bookId, DeviceType="web", code=200, **kwargs):
        """
        异步生成故事书的quiz
        :param bookId: (integer, path, required) 故事书ID
        :param content: (string, body, required) 故事内容
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-16
        url = f"https://{base_url}/api/book/{bookId}/quiz/generateAsync"
        payload = {
            "story": '',
            'targetAge': 5
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

    def quiz_task_status(self, authorization, bookId=0, taskId=0, DeviceType="web", code=200, **kwargs):
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

    def readingStatus(self, authorization, bookId=0, kidId=0, DeviceType="web", code=200, **kwargs):
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

    def book_rating(self, authorization, bookId=0, kidId=0, DeviceType="web", code=200, **kwargs):
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

    def book_recommend(self, authorization, age=0, bookId=0, localTime='', recommendType='', translateLanguage='zh', DeviceType="web", code=200, **kwargs):
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

    def continueplaying(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        故事书续播（Continue Playing）
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-21
        url = f"https://{base_url}/api/book/continuePlaying"
        payload = {
            "currentBookId": 123,
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

    def createBookTagType(self, authorization, allowMultipleTags=True, description='', name='', DeviceType="web", code=200):
        """
        创建故事书标签类型
        :param allowMultipleTags: (boolean, query, optional) 是否允许多选标签
        :param description: (string, query, optional) description
        :param name: (string, query, required) name
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-23
        url = f"https://{base_url}/api/book-tag-type/create"
        payload = {
            "allowMultipleTags": allowMultipleTags,
            "description": description,
            "name": name
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "创建故事书标签类型"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deleteBookTagType(self, authorization, id=0, DeviceType="web", code=200):
        """
        删除故事书标签
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-23
        url = f"https://{base_url}/api/book-tag-type/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除故事书标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def bookTagTypeList(self, authorization, page=0, size=10, DeviceType="web", code=200):
        """
        查询故事书标签类型列表
        :param page: (integer, query, optional) page
        :param size: (integer, query, optional) size
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-23
        url = f"https://{base_url}/api/book-tag-type/list"
        payload = {
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询故事书标签类型列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def createBookTag(self, authorization, tagDescription='', tagName='', tagTypeId=0, DeviceType="web", code=200, **kwargs):
        """
        创建故事书标签
        :param tagDescription: (string, query, optional) tagDescription
        :param tagName: (string, query, required) tagName
        :param tagTypeId: (integer, query, required) tagTypeId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-23
        url = f"https://{base_url}/api/book-tag/create"
        payload = {
            "tagDescription": tagDescription,
            "tagName": tagName,
            "tagTypeId": tagTypeId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "创建故事书标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def deleteBookTag(self, authorization, id=0, DeviceType="web", code=200, **kwargs):
        """
        删除书籍标签
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-23
        url = f"https://{base_url}/api/book-tag/{id}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "根据ID获取书籍标签详情"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getBookTagsByType(self, authorization, tagTypeId, page=0, size=10, DeviceType="web", code=200, **kwargs):
        """
        查询指定类型下的故事书标签列表
        :param tagTypeId: (integer, path, required) 标签类型ID
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页大小
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-23
        url = f"https://{base_url}/api/book-tag/by-type/{tagTypeId}"
        payload = {
            "page": page,
            "size": size
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询指定类型下的故事书标签列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def addTagToBook(self, authorization, bookId=0, tagId=0, DeviceType="web", code=200, **kwargs):
        """
        为故事书添加标签
        :param authorization: (string, header, required) AuthToken
        :param bookId: (integer, query, required) bookId
        :param tagId: (integer, query, required) tagId
        :param DeviceType: (string, header, required) android/ios/web
        :param code: (integer) 期望的HTTP状态码
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-23
        url = f"https://{base_url}/api/book-tag-relation/add"
        payload = {
            "bookId": bookId,
            "tagId": tagId
        }
        timestamp = str(int(time.time() * 1000))
        payload = self.request_body(payload, **kwargs)
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "为故事书添加标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def removeTagFromBook(self, authorization, bookId=0, tagId=0, DeviceType="web", code=200, **kwargs):
        """
        删除故事书与标签的关联关系
        :param authorization: (string, header, required) AuthToken
        :param bookId: (integer, query, required) bookId
        :param tagId: (integer, query, required) tagId
        :param DeviceType: (string, header, required) android/ios/web
        :param code: (integer) 期望的HTTP状态码
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-23
        url = f"https://{base_url}/api/book-tag-relation/remove"
        payload = {
            "bookId": bookId,
            "tagId": tagId
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers, params=payload)
        error_msg = "删除故事书与标签的关联关系"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def bookTagRelationList(self, authorization, bookId=0, page=0, size=10, tagId=0, DeviceType="web", code=200):
        """
        查询故事书标签关联列表
        :param authorization: (string, header, required) AuthToken
        :param bookId: (integer, query, optional) bookId
        :param page: (integer, query, optional) page
        :param size: (integer, query, optional) size
        :param tagId: (integer, query, optional) tagId
        :param DeviceType: (string, header, required) android/ios/web
        :param code: (integer) 期望的HTTP状态码
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-10-23
        url = f"https://{base_url}/api/book-tag-relation/list"
        payload = {
            "bookId": bookId,
            "tagId": tagId,
            "page": page,
            "size": size
        }

        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询故事书标签关联列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getBookTagsTree(self, authorization, bookId, DeviceType="web", code=200):
        """
        根据故事书ID查询标签树形结构
        :param authorization: (string, header, required) AuthToken
        :param bookId: (integer, path, required) 故事书ID
        :param DeviceType: (string, header, required) android/ios/web
        :param code: (integer) 期望的HTTP状态码
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.20.0  &  2025-10-23
        url = f"https://{base_url}/api/book/{bookId}/tags-tree"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "根据故事书ID查询标签树形结构"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def batchUpdateBookTags(self, authorization, bookId, tagIds, DeviceType="web", code=200, **kwargs):
        """
        批量更新故事书的标签
        :param authorization: (string, header, required) AuthToken
        :param bookId: (integer, path, required) 故事书ID
        :param tagIds: (array, body, required) 标签ID列表
        :param DeviceType: (string, header, required) android/ios/web
        :param code: (integer) 期望的HTTP状态码
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-01-15
        url = f"https://{base_url}/api/book/{bookId}/tags/batch-update"
        payload = tagIds
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def autoGenerateBookTags(self, authorization, bookId, DeviceType="web", code=200):
        """
        自动生成并保存故事书标签
        :param authorization: (string, header, required) AuthToken
        :param bookId: (integer, path, required) 故事书ID
        :param DeviceType: (string, header, required) android/ios/web
        :param code: (integer) 期望的HTTP状态码
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-01-15
        url = f"https://{base_url}/api/book/{bookId}/tags/auto-generate"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "自动生成并保存故事书标签"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def triggerTagBasedRecommendation(self, authorization, DeviceType="web", code=200):
        """
        手动触发基于标签的故事书推荐计算
        :param authorization: (string, header, required) AuthToken
        :param DeviceType: (string, header, required) android/ios/web
        :param code: (integer) 期望的HTTP状态码
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-01-15
        url = f"https://{base_url}/api/book/recommendation/tag-based/trigger"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "手动触发基于标签的故事书推荐计算"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def storybookRecommend(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        获取故事书推荐
        :param authorization: (string, header, required) AuthToken
        :param currentBookId: (integer, body, required) 当前阅读的书籍ID,用于作为推荐基准
        :param readBookIds: (array, body, optional) 已阅读的书籍ID列表，可以为空或null
        :param recommendCount: (integer, body, optional) 推荐数量，默认为1，最大为10
        :param recommendationFocus: (string, body, optional) 推荐焦点，默认为"content"
        :param DeviceType: (string, header, required) android/ios/web
        :param code: (integer) 期望的HTTP状态码
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.20.0  &  2025-10-17
        url = f"https://{base_url}/api/storybook/recommendation"
        payload = {
            "readBookIds": [1, 2, 3],
            "recommendCount": 5,
            "recommendationFocuås": "similar"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "获取故事书推荐"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def createormodifybook(self, authorization, language='zh', description='', bookName='', file=None, DeviceType="web", code=200, **kwargs):
        """
        创建(带bookId)/修改一本书籍
        :param bookId: (integer, query, optional) bookId
        :param category: (integer, query, required) category
        :param maxAge: (integer, query, required) maxAge
        :param minAge: (integer, query, required) minAge
        :param seriesId: (integer, query, optional) seriesId
        :param storyType: (string, query, optional) storyType
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-06
        url = f"https://{base_url}/api/book/createOrModifyBook"
        payload = {
            "category": '',
            "maxAge": 0,
            "minAge": 12,
            "seriesId": 0,
            "storyType": 'Fiction'
        }
        payload = self.request_body(payload, **kwargs)
        payload_data = {
            "bookName": bookName,
            "description": description,
            "language": language
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, params=payload, data=payload_data, files=file)
        error_msg = "创建(带bookId)/修改一本书籍"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getBookCategories(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        查询书籍分类树结构

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-06
        url = f"https://{base_url}/api/book/categories"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询书籍分类树结构"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def delete_book(self, authorization, bookId=0, DeviceType="web", code=200, **kwargs):
        """
        删除书籍
        :param bookId: (integer, path, required) bookId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-06
        url = f"https://{base_url}/api/book/{bookId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除书籍"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def book_details(self, authorization, bookId=0, translateLanguage='', DeviceType="web", code=200, **kwargs):
        """
        通过bookId查询书籍详情
        :param bookId: (integer, path, required) bookId
        :param translateLanguage: (string, query, optional) 目标翻译语言，用于翻译书籍名称和描述
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-06
        url = f"https://{base_url}/api/book/{bookId}"
        payload = {
            "translateLanguage": translateLanguage
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "通过bookId查询书籍详情"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def bookDetailUrl(self, authorization, bookId=0, DeviceType="web", code=200):
        """
        通过bookId获取书籍内容的下载链接
        :param bookId: (integer, path, required) bookId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-14
        url = f"https://{base_url}/api/book/bookDetailUrl/{bookId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "通过bookId获取书籍内容的下载链接"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def coverDetailUrl(self, authorization, bookId=0, DeviceType="web", code=200):
        """
        通过bookId获取书籍封面的下载链接
        :param bookId: (integer, path, required) bookId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-14
        url = f"https://{base_url}/api/book/coverDetailUrl/{bookId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "通过bookId获取书籍封面的下载链接"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def save_narration(self, authorization, bookId=123, narrationData=[], DeviceType="web", code=200, **kwargs):
        """
        保存故事书的领读数据
        :param req: (object, body, required) req
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-15
        url = f"https://{base_url}/api/book/narration/save"
        payload = {
            "bookId": bookId,
            "narrationData": json.dumps(narrationData),
            "narrationLanguage": "zh"
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "保存故事书的领读数据"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getNarrationData(self, authorization, bookId=123, narrationLanguage='zh', DeviceType="web", code=200, **kwargs):
        """
        获取故事书的领读数据
        :param bookId: (integer, query, required) 故事书ID
        :param narrationLanguage: (string, query, required) 领读语言代码（如zh、en、bn）
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-15
        url = f"https://{base_url}/api/book/narration/data"
        payload = {
            "bookId": bookId,
            "narrationLanguage": narrationLanguage
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "获取故事书的领读数据"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def narration_setEnabled(self, authorization, bookId=123, enabled=True, DeviceType="web", code=200, **kwargs):
        """
        设置故事书领读的启用状态
        :param bookId: (integer, query, required) 故事书ID
        :param enabled: (boolean, query, required) 是否启用
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-15
        url = f"https://{base_url}/api/book/narration/setEnabled"
        payload = {
            "bookId": bookId,
            "enabled": enabled
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "设置故事书领读的启用状态"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def regenerate_narration(self, authorization, bookId=123, DeviceType="web", code=200, **kwargs):
        """
        重新生成故事书的领读数据
        :param bookId: (integer, query, required) 故事书ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.21.0  &  2025-11-15
        url = f"https://{base_url}/api/book/narration/regenerate"
        payload = {
            "bookId": bookId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "重新生成故事书的领读数据"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def lexiLelevelMapping(self, authorization, DeviceType="web", code=200):
        """
        获取蓝思分数等级映射关系

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-27
        url = f"https://{base_url}/api/book/lexile/level/mapping"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取蓝思分数等级映射关系"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getQuerybyfilter(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        根据等级和认证过滤查询书籍
        :param certifications: (string, query, optional) 认证列表，逗号分隔，如 official,community。值：official（官方认证）、community（社区精选）
        :param levels: (string, query, optional) 等级列表，逗号分隔，如 A,B 或 A,B,C
        ‘’‘A: 蓝思分数 0-200
            B: 蓝思分数 200-400
            C: 蓝思分数 400-450
            D: 蓝思分数 450-500
            E: 蓝思分数 500+
        ’‘’
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-11-27
        url = f"https://{base_url}/api/book/queryByFilter"
        payload = {
            "certifications": 'official,community',
            "levels": 'A,B',
            "page": 0,
            "size": 10
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据等级和认证过滤查询书籍"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def bookLexile(self, authorization, bookId, DeviceType="web", code=200):
        """
        获取故事书的 lexile 分数
        :param bookId: (integer, path, required) 故事书ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-01
        url = f"https://{base_url}/api/book/{bookId}/lexile"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取故事书的 lexile 分数"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def lexile(self, authorization, bookId=0, lexileScore=750, DeviceType="web", code=200, **kwargs):
        """
        更新书籍Lexile分数
        :param bookId: (integer, path, required) 书籍ID
        :param lexileScore: (integer, query, required) Lexile分数 (0-2000)
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-01
        url = f"https://{base_url}/api/book/{bookId}/lexile"
        payload = {
            "lexileScore": lexileScore
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "更新书籍Lexile分数"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def batchUpdateOfficial(self, authorization, bookIds, DeviceType="web", code=200):
        """
        批量更新故事书的官方认证状态
        :param bookIds: (array, body, required) bookIds
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-03
        url = f"https://{base_url}/api/book/batch-update-official"
        payload = bookIds
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "批量更新故事书的官方认证状态"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def bookDetails(self, authorization, bookId, DeviceType="web", code=200):
        """
        通过bookId查询书籍详情
        :param bookId: (integer, path, required) bookId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-03
        url = f"https://{base_url}/api/book/{bookId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "通过bookId查询书籍详情"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def book_public_list(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        查询公开书籍列表
        :param categoryId: (integer, query, optional) 书籍分类ID（主题）
        :param key: (string, query, optional) 搜索关键词
        :param language: (string, query, optional) 书籍语言
        :param maxAge: (integer, query, optional) 最大年龄
        :param minAge: (integer, query, optional) 最小年龄
        :param page: (integer, query, optional) 页码
        :param recommendation: (string, query, optional) 推荐类型: RECENT, MOST_PLAYED, MOST_LIKED, MY_FAVORITES, MY_FOLLOWS, MY_STORYBOOKS
        :param size: (integer, query, optional) 每页数量
        :param translateLanguage: (string, query, optional) 目标翻译语言，用于翻译书籍名称和描述
        :param userAge: (integer, query, optional) 用户的年龄
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-03
        url = f"https://{base_url}/api/book/public/list"
        payload = {
            # "key": '',
            # "language": '',
            "maxAge": 10000,
            "minAge": 0,
            "page": 0,
            "size": 100000,
            # "translateLanguage": '',
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询公开书籍列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def guest_book_list(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        查询公开书籍列表（不需要鉴权）
        :param categoryId: (integer, query, optional) 书籍分类ID（主题）
        :param enableCache: (boolean, query, optional) 是否启用缓存
        :param key: (string, query, optional) 搜索关键词
        :param language: (string, query, optional) 书籍语言
        :param maxAge: (integer, query, optional) 最大年龄
        :param minAge: (integer, query, optional) 最小年龄
        :param page: (integer, query, optional) 页码
        :param recommendation: (string, query, optional) 推荐类型: RECENT, MOST_PLAYED, MOST_LIKED
        :param size: (integer, query, optional) 每页数量
        :param translateLanguage: (string, query, optional) 目标翻译语言，用于翻译书籍名称和描述
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-04
        url = f"https://{base_url}/api/book/public/list/guest"
        payload = {
            # "enableCache": False,
            # "key": '',
            # "language": '',
            # "maxAge": 6,
            # "minAge": 3,
            "page": 0,
            # "recommendation": 'RECENT',
            "size": 10000,
            # "translateLanguage": ''
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询公开书籍列表（不需要鉴权）"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def searchBook(self, authorization, DeviceType="web", code=200, id_df=False, **kwargs):
        """
        根据书名/作者名/标签搜索书籍
        :param key: (string, query, optional) key
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :param tags: (array, query, required) tags
        :param type: (string, query, required) type
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-04
        url = f"https://{base_url}/api/book/search"
        payload = {
            "key": '',
            "page": 0,
            "size": 1000,
            "tags": '',
            "type": ''
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据书名/作者名/标签搜索书籍"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            if not id_df:
                return response
            else:
                return DataFrame(response['data'], columns=["id"])
        except json.decoder.JSONDecodeError:
            return False

    def translation_trigger(self, authorization, bookIds, DeviceType="web"):
        """
        触发故事书翻译
        :param bookIds: (string, query, required) bookIds
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/api/book/translation/trigger"
        payload = {
            "bookIds": bookIds
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "触发故事书翻译"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def languagePack(self, authorization, bookId, languageCode, DeviceType="web"):
        """
        根据故事书ID和语言代码查询语言包地址
        :param bookId: (integer, path, required) bookId
        :param languageCode: (string, path, required) languageCode
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/api/book/{bookId}/language-pack/{languageCode}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "根据故事书ID和语言代码查询语言包地址"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def book_upload(self, authorization, bookId, file, DeviceType="web"):
        """
        上传书籍内容json
        :param bookId: (integer, query, required) bookId
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/api/book/upload"
        payload = {
            "bookId": bookId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, data=payload, files=file)
        error_msg = "上传书籍内容json"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def createBookWithName(self, authorization, bookName, DeviceType="web"):
        """
        给一本书的名字，根据该名字创建一本故事书
        :param bookName: (string, path, required) bookName
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-10
        url = f"https://{base_url}/api/book/createBookWithName/{bookName}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "给一本书的名字，根据该名字创建一本故事书"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def storyBoard(self, authorization, bookId, DeviceType="web"):
        """
        查询故事书Storyboard内容
        :param bookName: (string, path, required) bookName
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-11
        url = f"https://{base_url}/api/book/{bookId}/storyboard"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询故事书Storyboard内容"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def storyBookStyle(self, authorization, DeviceType="web"):
        """故事书风格生成"""
        # Create Data:  V1.22.0  &  2025-12-11
        url = f"https://{base_url}/api/aiserver/storybook/style"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "故事书风格生成"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def generateCoverimageInfo(self, authorization, DeviceType="web", **kwargs):
        """
        生成封面图片的提示词和角色信息
        :param bookName: (string, path, required) bookName
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-11
        url = f"https://{base_url}/api/aiserver/storybook/storyboard/coverimage"
        payload = {
            "characters": [
                {
                    "name": "Dusty",
                    "description": "Dusty is a small, perfectly round dust bunny composed of exceptionally soft, fluffy grey dust with gentle hints of light blue and lavender woven throughout his body. He does not wear any clothes. He lacks distinct limbs, moving by hopping and wiggling his entire body. His face is simple, dominated by two large, shiny black button-like eyes that sparkle with curiosity and express his emotions. When he's scared, he shrinks a little, and when he's brave, he puffs up his fluff to appear bigger.",
                    "description1": "Dusty is a small, perfectly round dust bunny composed of exceptionally soft, fluffy grey dust with gentle hints of light blue and lavender woven throughout his body. He does not wear any clothes. He lacks distinct limbs, moving by hopping and wiggling his entire body. His face is simple, dominated by two large, shiny black button-like eyes that sparkle with curiosity and express his emotions. When he's scared, he shrinks a little, and when he's brave, he puffs up his fluff to appear bigger.",
                    "url": "https://creator.qakjukl.net/api/book/content?contentKey=storyboard/characters/1763196508038_Ut4Ny3rt"
                }
            ],
            "story": "Dusty the dust bunny hummed a wee, wobbly tune. He saw a sparkly light! It danced under the big chair. Oh, his fluffy self might get tangled if he left his snug spot. But the light called to him. It whispered of secrets!\n\nDusty puffed up. He took a tiny hop. The light shimmered brighter! He wiggled a bit closer. A big, scary dust clump blocked his way. \"Oh dear!\" squeaked Dusty. He squeezed past. The light pulsed, warm and inviting.\n\nHe took another brave hop. A crumb mountain rose high. \"Too tall!\" he cried. But the light winked. Dusty tumbled over it, rolling, rolling, rolling! He landed with a soft thump. The light glowed like a tiny sun.\n\nOne more leap! A giant, fuzzy sock lay flat. It stretched like a long, dark cave. Dusty shivered. He hummed a bit louder, a braver tune now. He scurried through the soft, dark tunnel. He popped out! The sparkly light was right there. It was a lost button, shiny and round. Dusty giggled. He had found it!",
            "style": "A comic cartoon style, crisp, bold brushstrokes that outline shapes with a playful, energetic edge. The color tones are bright yet balanced, with a flat, even finish that pops off the page without overwhelming. The drawing skill is precise but exaggerated, focusing on thick, confident lines and simplified forms that are instantly recognizable and fun. Lighting is flat and uniform, giving a cheerful, cartoonish clarity that keeps the tone light and engaging.",
            "title": "Dusty the Dust Bunny's Adventure"
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "生成封面图片的提示词和角色信息"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def generateCoverimage(self, authorization, DeviceType="web", **kwargs):
        """使用提示词和角色信息生成最终的封面图片"""
        # Create Data:  V1.22.0  &  2025-12-11
        url = f"https://{base_url}/api/aiserver/storybook/image/nano_create"
        payload = {
            "characters": [
                {
                    "name": "Dusty",
                    "description": "Dusty is a small, perfectly round dust bunny composed of exceptionally soft, fluffy grey dust with gentle hints of light blue and lavender woven throughout his body. He does not wear any clothes. He lacks distinct limbs, moving by hopping and wiggling his entire body. His face is simple, dominated by two large, shiny black button-like eyes that sparkle with curiosity and express his emotions. When he's scared, he shrinks a little, and when he's brave, he puffs up his fluff to appear bigger.",
                    "description1": "Dusty is a small, perfectly round dust bunny composed of exceptionally soft, fluffy grey dust with gentle hints of light blue and lavender woven throughout his body. He does not wear any clothes. He lacks distinct limbs, moving by hopping and wiggling his entire body. His face is simple, dominated by two large, shiny black button-like eyes that sparkle with curiosity and express his emotions. When he's scared, he shrinks a little, and when he's brave, he puffs up his fluff to appear bigger.",
                    "url": "https://creator.qakjukl.net/api/book/content?contentKey=storyboard/characters/1763196508038_Ut4Ny3rt"
                }
            ],
            "prompt": "A comic cartoon style, crisp, bold brushstrokes that outline shapes with a playful, energetic edge. The color tones are bright yet balanced, with a flat, even finish that pops off the page without overwhelming. The drawing skill is precise but exaggerated, focusing on thick, confident lines and simplified forms that are instantly recognizable and fun. Lighting is flat and uniform, giving a cheerful, cartoonish clarity that keeps the tone light and engaging. A typography with a soft, fuzzy texture, like a dust bunny, with subtle shimmers of light emanating from within, in a playful, slightly wobbly yet bold font, with hints of very soft grey and pale yellow, as if lit by a tiny, warm glow. says \"Dusty the Dust Bunny's Adventure\". An extreme close-up, low-angle shot, making a tiny, fluffy, light grey dust bunny named Dusty appear monumental as he stands bravely before an enormous, soft, dark blue sock that stretches across the scene like a vast, intimidating cave entrance. Dusty is puffing up his fluff to appear bigger, with his large, shiny black button-like eyes sparkling with curiosity, gazing forward with a determined front view. The sock is slightly frayed at the opening, hinting at its age. In the distance, just beyond the sock's mouth, a single, tiny, golden-yellow light gleams invitingly. The setting is a dusty, shadowy floor, with giant crumbs, fuzz, and other household debris creating a miniature, adventurous landscape around Dusty. The lighting is soft and warm from Dusty's perspective, emanating subtly from the distant light source, contrasting with the cool, dim shadows of the floor. The color palette is dominated by muted blues, greys, and browns, with a vibrant, warm glow from the distant light.",
            "aspect_ratio": "16:9",
            "names": ["Dusty"],
            "task_id": "845705ff-c5c6-4aa2-9b5b-402519e8d86b"
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "使用提示词和角色信息生成最终的封面图片"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def generateCoverimageStatus(self, authorization, request_id, DeviceType="web"):
        """
        查看提示词和角色信息生成最终的封面图片状态
        :param request_id: 提示词和角色信息生成最终的封面图片任务请求id
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.22.0  &  2025-12-11
        url = f"https://{base_url}/api/aiserver/storybook/image/status"
        payload = {
            "request_id": request_id
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "使用提示词和角色信息生成最终的封面图片"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def upload_book_cover(self, authorization, bookId, file, DeviceType="web"):
        """
        修改封面
        :param bookId: (integer, query, required) bookId
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-11
        url = f"https://{base_url}/api/book/uploadCover"
        payload = {
            "bookId": bookId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, params=payload, data=payload, files=file)
        error_msg = "修改封面"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getBookMultilingual(self, authorization, bookId, DeviceType="web"):
        """
        查询故事书的所有多语言翻译
        :param bookId: (integer, path, required) 故事书ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-22
        url = f"https://{base_url}/api/book/{bookId}/multilingual"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询故事书的所有多语言翻译"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def saveBookMultilingual(self, authorization, bookId, title, key='en', description='', DeviceType="web"):
        """
        保存故事书的多语言翻译
        :param bookId: (integer, path, required) 故事书ID
        :param request: (object, body, required) request
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-22
        url = f"https://{base_url}/api/book/{bookId}/multilingual"
        payload = {
            "translations": {
                key: {
                    "title": title,
                    "description": description
                }
            }
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "保存故事书的多语言翻译"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def addProcesstaskVoicePack(self, authorization, bookId, languageCode, DeviceType="web"):
        """
        添加语言包处理任务到队列
        :param bookId: (integer, query, required) bookId
        :param languageCode: (string, query, required) languageCode
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-22
        url = f"https://{base_url}/api/book/voicePack/addProcessTask"
        payload = {
            "bookId": bookId,
            "languageCode": languageCode
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "添加语言包处理任务到队列"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def uploadVoicePack(self, authorization, bookId, languageCode, file=None, DeviceType="web"):
        """
        上传并保存故事书语言包
        :param bookId: (integer, query, required) bookId
        :param languageCode: (string, query, required) languageCode
        :param file: (file, formData, optional) 上传文件
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-22
        url = f"https://{base_url}/api/book/voicePack/upload"
        payload = {
            "bookId": bookId,
            "languageCode": languageCode
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType, Content_Type='multipart/form-data')

        response = requests.request("POST", url, headers=headers, data=payload, files=file)
        error_msg = "上传并保存故事书语言包"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def pinSeries(self, authorization, seriesId, age, isPinned=False, DeviceType="web", code=200):
        """
        更新故事书系列pin状态
        :param seriesId: (integer, path, required) 系列ID
        :param age: (integer, query, required) 年龄段
        :param isPinned: (boolean, query, required) 是否pin：true-pin，false-取消pin
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/api/book/series/{seriesId}/pin"
        payload = {
            "age": age,
            "isPinned": isPinned
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "更新故事书系列pin状态"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def pinnedSeriesByAge(self, authorization, age, DeviceType="web", code=200):
        """
        按年龄查询被pin的系列列表
        :param age: (integer, query, required) 年龄
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/api/book/series/pinned/byAge"
        payload = {
            "age": age
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "按年龄查询被pin的系列列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def bookSeries(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        查询故事书系列列表
        :param bookCoverSize: (integer, query, optional) 展示书籍封面数量，默认3
        :param includeBookCount: (boolean, query, optional) 是否包含书籍数量，默认false
        :param includeBookCover: (boolean, query, optional) 是否展示书籍封面数组，默认false
        :param kidId: (integer, query, optional) 孩子ID，用于年龄过滤和pin优先排序
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :param total: (boolean, query, optional) 是否查询所有数据，默认false进行分页
        :param translateLanguage: (string, query, optional) 目标翻译语言，用于翻译系列标题和描述
        :param visibleOnly: (boolean, query, optional) 是否只查询可见的系列，默认true只查询可见的
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/api/book/series"
        payload = {
            "bookCoverSize": 3,
            "includeBookCount": False,
            "includeBookCover": False,
            "kidId": 0,
            "page": 0,
            "size": 20,
            "total": False,
            "translateLanguage": '',
            "visibleOnly": True
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询故事书系列列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def seriesByAge(self, authorization, DeviceType="web", code=200, **kwargs):
        """
        按年龄查询系列列表
        :param age: (integer, query, required) 年龄
        :param includeBookCount: (boolean, query, optional) 是否包含书籍数量，默认false
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :param translateLanguage: (string, query, optional) 目标翻译语言，用于翻译系列标题和描述
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/api/book/series/byAge"
        payload = {
            "age": 5,
            "includeBookCount": False,
            "page": 0,
            "size": 20,
            "translateLanguage": ''
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "按年龄查询系列列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getPinnedbooks(self, authorization, seriesId, DeviceType="web", code=200):
        """
        查询系列下所有被pin的故事书
        :param seriesId: (integer, path, required) 系列ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/api/book/series/{seriesId}/pinnedBooks"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询系列下所有被pin的故事书"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getBooksBySeriesId(self, authorization, seriesId, DeviceType="web", code=200, **kwargs):
        """
        根据系列ID查询故事书列表
        :param seriesId: (integer, path, required) 系列ID
        :param page: (integer, query, optional) 页码
        :param searchKey: (string, query, optional) 搜索关键词，用于模糊搜索故事书标题
        :param size: (integer, query, optional) 每页数量
        :param status: (integer, query, optional) 故事书状态：0-私有，1-公开，2-待审核，3-被拒绝，4-已删除
        :param translateLanguage: (string, query, optional) 目标翻译语言，用于翻译书籍标题和描述
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/api/book/series/{seriesId}/books"
        payload = {
            "page": 0,
            "searchKey": '',
            "size": 20,
            "status": 1,
            "translateLanguage": ''
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据系列ID查询故事书列表"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def pinBook(self, authorization, bookId, isPinned=False, DeviceType="web", code=200):
        """
        更新故事书pin状态
        :param bookId: (integer, path, required) 故事书ID
        :param isPinned: (boolean, query, required) 是否pin：true-pin，false-取消pin
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-23
        url = f"https://{base_url}/api/book/{bookId}/pin"
        payload = {
            "isPinned": isPinned
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "更新故事书pin状态"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def search_book(self, authorization, DeviceType="web", **kwargs):
        """
        app端根据书名/作者名/标签搜索书籍
        :param key: (string, query, optional) key
        :param levels: (string, query, optional) levels
        :param official: (integer, query, optional) official
        :param page: (integer, query, optional) 页码
        :param selected: (integer, query, optional) selected
        :param size: (integer, query, optional) 每页数量
        :param tags: (array, query, optional) tags
        :param type: (string, query, required) PUBLIC, FAVORITE, MINE
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-24
        url = f"https://{base_url}/api/book/search"
        payload = {
            "key": '',
            "levels": '',
            "selected": 1,
            "official": 1,
            "page": 0,
            "size": 20,
            "tags": '',
            "type": 'PUBLIC'
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据书名/作者名/标签搜索书籍"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def userFavoriteItems(self, authorization, DeviceType="web"):
        """
        获取当前用户的所有收藏记录(仅id)

        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-24
        url = f"https://{base_url}/api/book/favoriteItems"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取当前用户的所有收藏记录(仅id)"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def favorite(self, authorization, bookId, DeviceType="web"):
        """
        添加收藏
        :param bookId: (integer, query, required) bookId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-24
        url = f"https://{base_url}/api/book/favorite"
        payload = {
            "bookId": bookId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "添加收藏"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def deleteFavorite(self, authorization, bookId, DeviceType="web"):
        """
        移除收藏
        :param bookId: (integer, query, required) bookId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-24
        url = f"https://{base_url}/api/book/favorite"
        payload = {
            "bookId": bookId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers, params=payload)
        error_msg = "移除收藏"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def book_content(self, authorization, bookId, DeviceType="web"):
        """
        查询故事书的content
        :param bookId: (integer, path, required) 故事书ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-25
        url = f"https://{base_url}/api/book/{bookId}/content"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询故事书的content"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def processlayers(self, authorization, bookIds, DeviceType="web", code=200, **kwargs):
        """
        processBookLayers
        :param bookIds: (string, query, required) bookIds
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2025-12-25
        url = f"https://{base_url}/api/book/processLayers"
        payload = {
            "bookIds": bookIds
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "processBookLayers"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        try:
            response = response.json()
            return response
        except json.decoder.JSONDecodeError:
            return False

    def getSupportedlanguages(self, authorization, bookId, DeviceType="web"):
        """
        查询故事书支持的多语言
        :param bookId: (integer, path, required) 故事书ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2026-01-05
        url = f"https://{base_url}/api/book/{bookId}/supportedLanguages"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "查询故事书支持的多语言"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def public_book_details(self, authorization, bookId, translateLanguage='en', DeviceType="web"):
        """
        通过bookId查询书籍详情
        :param bookId: (integer, path, required) bookId
        :param translateLanguage: (string, query, optional) 目标翻译语言，用于翻译书籍名称和描述
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2026-01-05
        url = f"https://{base_url}/api/book/public/{bookId}"
        payload = {
            "translateLanguage": translateLanguage
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "通过bookId查询书籍详情"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def generate_book_quiz(self, authorization, bookId, content, DeviceType="web", code=200, **kwargs):
        """
        生成故事书的quiz
        :param bookId: (integer, path, required) 故事书ID
        :param content: (string, body, required) 故事内容
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2026-01-05
        url = f"https://{base_url}/api/book/{bookId}/quiz/generate"
        payload = {
            "content": content
        }
        payload = self.request_body(payload, **kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, json=payload)
        error_msg = "生成故事书的quiz"
        assert response.status_code == code, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def bookShare(self, authorization, token, translateLanguage, DeviceType="web"):
        """
        通过分享令牌获取书籍
        :param token: (string, query, required) token
        :param translateLanguage: (string, query, optional) translateLanguage
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2026-01-05
        url = f"https://{base_url}/api/book/share"
        payload = {
            "token": token,
            "translateLanguage": translateLanguage
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "通过分享令牌获取书籍"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def shareBook(self, authorization, bookId, DeviceType="web"):
        """
        创建私有书籍分享链接
        :param bookId: (integer, path, required) bookId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.19.0  &  2026-01-05
        url = f"https://{base_url}/api/book/{bookId}/share"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers)
        error_msg = "创建私有书籍分享链接"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def voice_model_list(self, authorization, DeviceType="web"):
        """
        获取用户语音模型列表
        :param voicePackId: (integer, path, required) voicePackId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/voice-clone/model/list"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取语音包信息"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def book_voice_packs(self, authorization, bookId, kidId, languageCode, voiceModelId, DeviceType="web"):
        """
        根据指定条件获取语音包
        :param bookId: (integer, query, required) bookId
        :param kidId: (integer, query, optional) kidId
        :param languageCode: (string, query, required) languageCode
        :param voiceModelId: (string, query, required) voiceModelId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/book/voice-packs"
        payload = {
            "bookId": bookId,
            "kidId": kidId,
            "languageCode": languageCode,
            "voiceModelId": voiceModelId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据指定条件获取语音包"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def generate_voice_pack(self, authorization, bookId, kidId, languageCode, voiceModelId, DeviceType="web"):
        """
        生成故事书语音包
        :param bookId: (integer, query, required) bookId
        :param kidId: (integer, query, required) kidId
        :param languageCode: (string, query, required) languageCode
        :param voiceModelId: (string, query, required) voiceModelId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/book/voice-pack/generate"
        payload = {
            "bookId": bookId,
            "kidId": kidId,
            "languageCode": languageCode,
            "voiceModelId": voiceModelId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "生成故事书语音包"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def voice_pack_details(self, authorization, voicePackId=0, DeviceType="web"):
        """
        获取语音包信息
        :param voicePackId: (integer, path, required) voicePackId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/book/voice-pack/{voicePackId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取语音包信息"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def incrementReadCount(self, authorization, bookId, DeviceType="web"):
        """
        增加一次阅读
        :param bookId: (integer, query, required) bookId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/book/incrementReadCount"
        payload = {
            "bookId": bookId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "增加一次阅读"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def getReadingStatus(self, authorization, bookId, kidId, DeviceType="web"):
        """
        检查kid是否读过某本故事书
        :param bookId: (integer, path, required) 故事书ID
        :param kidId: (integer, query, required) 孩子ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/book/{bookId}/reading-status"
        payload = {
            "kidId": kidId
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "检查kid是否读过某本故事书"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def recordReading(self, authorization, bookId, kidId, platform, DeviceType="web"):
        """
        记录书籍阅读，故事书阅读完上报
        :param bookId: (integer, query, required) bookId
        :param kidId: (integer, query, optional) kidId
        :param platform: (string, query, optional) 平台信息，APP、WEB
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/book/recordReading"
        payload = {
            "bookId": bookId,
            "kidId": kidId,
            "platform": platform
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "记录书籍阅读，故事书阅读完上报"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def reportBook(self, authorization, bookId, comment, pageNumber, reason, DeviceType="web"):
        """
        举报书籍
        :param bookId: (integer, path, required) bookId
        :param comment: (string, query, optional) comment
        :param pageNumber: (integer, query, optional) pageNumber
        :param reason: (string, query, required) reason
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/book/{bookId}/report"
        payload = {
            "comment": comment,
            "pageNumber": pageNumber,
            "reason": reason
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("POST", url, headers=headers, params=payload)
        error_msg = "举报书籍"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def series_details(self, authorization, seriesId, includeBookCount=False, translateLanguage='', DeviceType="web"):
        """
        查询单个故事书系列
        :param seriesId: (integer, path, required) 系列ID
        :param includeBookCount: (boolean, query, optional) 是否包含书籍数量，默认false
        :param translateLanguage: (string, query, optional) 目标翻译语言，用于翻译系列标题和描述
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/book/series/{seriesId}"
        payload = {
            "includeBookCount": includeBookCount,
            "translateLanguage": translateLanguage
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询单个故事书系列"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def delete_series(self, authorization, seriesId, DeviceType="web"):
        """
        删除故事书系列
        :param seriesId: (integer, path, required) 系列ID
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/book/series/{seriesId}"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("DELETE", url, headers=headers)
        error_msg = "删除故事书系列"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def seriesBooks(self, authorization, seriesId, page=0, searchKey='', size=10, status=0,
                    translateLanguage='en', DeviceType="web"):
        """
        根据系列ID查询故事书列表
        :param seriesId: (integer, path, required) 系列ID
        :param page: (integer, query, optional) 页码
        :param searchKey: (string, query, optional) 搜索关键词，用于模糊搜索故事书标题
        :param size: (integer, query, optional) 每页数量
        :param status: (integer, query, optional) 故事书状态：0-私有，1-公开，2-待审核，3-被拒绝，4-已删除
        :param translateLanguage: (string, query, optional) 目标翻译语言，用于翻译书籍标题和描述
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/book/series/{seriesId}/books"
        payload = {
            "page": page,
            "searchKey": searchKey,
            "size": size,
            "status": status,
            "translateLanguage": translateLanguage
        }
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "根据系列ID查询故事书列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def userPublicbooks(self, authorization, userId, DeviceType="web", **kwargs):
        """
        查询指定用户的公开故事书列表
        :param userId: (integer, path, required) 用户ID
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :param translateLanguage: (string, query, optional) 目标翻译语言，用于翻译书籍标题和描述
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/book/user/{userId}/publicBooks"
        payload = {
            "page": 0,
            "size": 20,
            "translateLanguage": ''
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询指定用户的公开故事书列表"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def userOriginalBooks(self, authorization, contributorId, DeviceType="web", **kwargs):
        """
        查询某个用户贡献过的原始故事书
        :param contributorId: (integer, path, required) contributorId
        :param page: (integer, query, optional) 页码
        :param size: (integer, query, optional) 每页数量
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/book/{contributorId}/original-books"
        payload = {
            "page": 0,
            "size": 20
        }
        payload.update(kwargs)
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers, params=payload)
        error_msg = "查询某个用户贡献过的原始故事书"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response

    def voice_clone_model(self, authorization, DeviceType="web"):
        """
        获取用户语音模型列表
        :param voicePackId: (integer, path, required) voicePackId
        :return: 接口原始返回（已 json 解析）
        """
        # Create Data:  V1.24.0  &  2026-01-06
        url = f"https://{base_url}/api/voice-clone/model"
        timestamp = str(int(time.time() * 1000))
        headers = self.request_header(timestamp, authorization, DeviceType)

        response = requests.request("GET", url, headers=headers)
        error_msg = "获取语音包信息"
        assert response.status_code == 200, f"{error_msg}失败，url->{url}，失败信息->{response.reason}{response.content}"
        response = response.json()
        return response