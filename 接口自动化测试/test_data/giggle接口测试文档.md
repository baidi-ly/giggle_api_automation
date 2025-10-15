# 接口测试文档 develop vs release/1.20.0

## 1. 版本概述

**版本号**: develop vs release/1.20.0  
**发布日期**: 2025年1月  
**测试环境**: [待填写]  
**生产环境**: [待填写]  

### 1.1 主要功能更新
- **扭蛋活动系统**: 新增获取活动列表接口
- **捐赠订单系统**: 新增支出记录管理功能（更新备注、分页查询）
- **推荐系统**: 新增A/B测试支持
- **管理后台**: 增强推荐规则管理功能
- **学校管理系统**: 新增班级学生分组管理功能、课程资源管理功能
- **故事书管理**: 新增首页语音上传和查询功能、Quiz生成和管理功能

### 1.2 数据库变更
- 新增 `donate_expend` 表：支出记录管理
- 修改 `books_multilingual` 表：增加首页语音字段
- 相关表结构优化以支持A/B测试功能

## 2. 新增接口测试

### 2.1 扭蛋活动相关接口 (GachaActivityController)

#### 2.1.1 获取扭蛋活动列表
**接口地址**: `GET /activity/gacha/list`  
**接口描述**: 获取当前正在进行的扭蛋活动  
**请求方式**: GET  
**是否需要认证**: 否 (@PublicApi)  
**控制器**: GachaActivityController.getActivityList()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| language | String | 否 | - | 语言代码 | "zh" |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "activities": [
      {
        "id": 1,
        "name": "春节扭蛋活动",
        "startTime": "2025-01-01T00:00:00",
        "endTime": "2025-01-31T23:59:59",
        "status": "ACTIVE"
      }
    ]
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| GACHA-LIST-001 | 正常获取活动列表 | 返回活动列表 | P1 |
| GACHA-LIST-002 | 指定语言获取 | 返回对应语言的活动 | P2 |
| GACHA-LIST-003 | 无活动时查询 | 返回空列表 | P2 |

---

### 2.2 捐赠订单相关接口 (DonateOrderController)

#### 2.2.1 更新支出记录备注
**接口地址**: `POST /expend/update-remark`  
**接口描述**: 更新支出记录的备注、详情URL和分类  
**请求方式**: POST  
**是否需要认证**: 否 (@PublicApi)  
**控制器**: DonateOrderController.updateExpendRemark()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| transactionId | String | 是 | @NotBlank | 交易ID | "tx_123456789" |
| remark | String | 否 | - | 备注信息 | "购买服务器" |
| detailUrl | String | 否 | - | 详情URL | "https://example.com/detail" |
| category | String | 否 | - | 分类 | "infrastructure" |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "updated": true
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| EXPEND-UPDATE-001 | 正常更新备注 | 返回更新成功 | P1 |
| EXPEND-UPDATE-002 | 交易ID不存在 | 返回交易不存在错误 | P1 |
| EXPEND-UPDATE-003 | 交易ID为空 | 返回参数错误 | P1 |
| EXPEND-UPDATE-004 | 更新所有字段 | 返回更新成功 | P2 |

---

#### 2.2.2 分页查询支出记录列表
**接口地址**: `GET /expend/list`  
**接口描述**: 分页查询支出记录列表  
**请求方式**: GET  
**是否需要认证**: 否 (@PublicApi)  
**控制器**: DonateOrderController.getExpendList()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| page | Int | 否 | @Min(0) | 页码，默认0 | 0 |
| size | Int | 否 | @Min(1) @Max(100) | 每页数量，默认10 | 10 |
| keyword | String | 否 | - | 搜索关键词 | "服务器" |
| category | String | 否 | - | 分类筛选 | "infrastructure" |
| startDate | String | 否 | - | 开始日期 | "2025-01-01" |
| endDate | String | 否 | - | 结束日期 | "2025-01-31" |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "content": [
      {
        "id": 1,
        "transactionId": "tx_123456789",
        "amount": "100.00",
        "category": "infrastructure",
        "remark": "购买服务器",
        "detailUrl": "https://example.com/detail",
        "createdAt": "2025-01-15T10:30:00"
      }
    ],
    "totalElements": 50,
    "totalPages": 5,
    "size": 10,
    "number": 0
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| EXPEND-LIST-001 | 正常分页查询 | 返回支出记录列表 | P1 |
| EXPEND-LIST-002 | 带关键词搜索 | 返回匹配的记录 | P2 |
| EXPEND-LIST-003 | 按分类筛选 | 返回指定分类的记录 | P2 |
| EXPEND-LIST-004 | 按日期范围筛选 | 返回日期范围内的记录 | P2 |
| EXPEND-LIST-005 | 无数据时查询 | 返回空列表 | P2 |

---

### 2.3 学校管理相关接口 (SchoolController)

#### 2.3.1 更新班级学生默认分组
**接口地址**: `PUT /school/class/{classId}/groups`  
**接口描述**: 更新班级学生默认分组  
**请求方式**: PUT  
**是否需要认证**: 是  
**控制器**: SchoolController.updateClassStudentGroups()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| classId | Long | 是 | @Min(1) | 班级ID | 123 |
| groups | List<SchoolClassStudentGroupReq> | 是 | @NotEmpty | 分组信息 | [{"name":"组1","studentIds":[1,2,3]}] |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "updated": true
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| CLASS-GROUPS-001 | 正常更新分组 | 返回更新成功 | P1 |
| CLASS-GROUPS-002 | 班级不存在 | 返回班级不存在错误 | P1 |
| CLASS-GROUPS-003 | 分组信息为空 | 返回参数错误 | P1 |
| CLASS-GROUPS-004 | 学生ID不存在 | 返回学生不存在错误 | P2 |

---

#### 2.3.2 Normal课程资源列表
**接口地址**: `GET /lesson/resource/normalCourse`  
**接口描述**: Normal课程资源列表  
**请求方式**: GET  
**是否需要认证**: 是  
**控制器**: SchoolController.normalCourseList()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| page | Int | 否 | @Min(0) | 页码，默认0 | 0 |
| size | Int | 否 | @Min(1) @Max(100) | 每页数量，默认10 | 10 |
| keyword | String | 否 | - | 搜索关键词 | "数学" |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "content": [
      {
        "id": 1,
        "title": "小学数学基础",
        "description": "适合小学生的数学课程",
        "level": "ELEMENTARY",
        "duration": 30,
        "createdAt": "2025-01-15T10:30:00"
      }
    ],
    "totalElements": 100,
    "totalPages": 10
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| COURSE-LIST-001 | 正常获取课程列表 | 返回课程列表 | P1 |
| COURSE-LIST-002 | 带关键词搜索 | 返回匹配的课程 | P2 |
| COURSE-LIST-003 | 分页查询 | 返回分页数据 | P2 |
| COURSE-LIST-004 | 无数据时查询 | 返回空列表 | P2 |

---

#### 2.3.3 测验列表
**接口地址**: `GET /lesson/resource/quiz`  
**接口描述**: 测验列表  
**请求方式**: GET  
**是否需要认证**: 是  
**控制器**: SchoolController.quizList()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| page | Int | 否 | @Min(0) | 页码，默认0 | 0 |
| size | Int | 否 | @Min(1) @Max(100) | 每页数量，默认10 | 10 |
| keyword | String | 否 | - | 搜索关键词 | "英语" |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "content": [
      {
        "id": 1,
        "title": "英语词汇测验",
        "description": "基础英语词汇测试",
        "questionCount": 20,
        "duration": 15,
        "createdAt": "2025-01-15T10:30:00"
      }
    ],
    "totalElements": 50,
    "totalPages": 5
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| QUIZ-LIST-001 | 正常获取测验列表 | 返回测验列表 | P1 |
| QUIZ-LIST-002 | 带关键词搜索 | 返回匹配的测验 | P2 |
| QUIZ-LIST-003 | 分页查询 | 返回分页数据 | P2 |
| QUIZ-LIST-004 | 无数据时查询 | 返回空列表 | P2 |

---

### 2.4 故事书管理相关接口 (BookController)

#### 2.4.1 上传故事书首页语音
**接口地址**: `POST /book/{bookId}/indexAudio/{language}`  
**接口描述**: 上传并保存故事书首页语音  
**请求方式**: POST  
**是否需要认证**: 是  
**控制器**: BookController.uploadBookIndexAudio()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| bookId | Long | 是 | @Min(1) | 故事书ID | 123 |
| language | String | 是 | @NotBlank | 语言代码 | "zh" |
| audioFile | MultipartFile | 是 | @NotNull | 音频文件 | audio.mp3 |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "s3Key": "book/index-audio/123/zh/audio_abc123.mp3"
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| BOOK-AUDIO-UPLOAD-001 | 正常上传音频 | 返回S3 Key | P1 |
| BOOK-AUDIO-UPLOAD-002 | 故事书不存在 | 返回故事书不存在错误 | P1 |
| BOOK-AUDIO-UPLOAD-003 | 音频文件为空 | 返回文件错误 | P1 |
| BOOK-AUDIO-UPLOAD-004 | 不支持的语言 | 返回语言不支持错误 | P1 |
| BOOK-AUDIO-UPLOAD-005 | 音频格式不支持 | 返回格式错误 | P2 |

---

#### 2.4.2 查询故事书首页语音
**接口地址**: `GET /book/{bookId}/indexAudio/{language}`  
**接口描述**: 查询故事书首页语音  
**请求方式**: GET  
**是否需要认证**: 否 (@PublicApi)  
**控制器**: BookController.getBookIndexAudio()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| bookId | Long | 是 | @Min(1) | 故事书ID | 123 |
| language | String | 是 | @NotBlank | 语言代码 | "zh" |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "indexAudioKey": "book/index-audio/123/zh/audio_abc123.mp3"
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| BOOK-AUDIO-GET-001 | 正常查询音频Key | 返回音频Key | P1 |
| BOOK-AUDIO-GET-002 | 故事书不存在 | 返回故事书不存在错误 | P1 |
| BOOK-AUDIO-GET-003 | 语言不支持 | 返回语言不支持错误 | P1 |
| BOOK-AUDIO-GET-004 | 音频不存在 | 返回音频不存在错误 | P1 |

---

#### 2.4.3 生成故事书的quiz
**接口地址**: `POST /book/{bookId}/quiz/generate`  
**接口描述**: 生成故事书的quiz  
**请求方式**: POST  
**是否需要认证**: 是  
**控制器**: BookController.generateBookQuiz()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| bookId | Long | 是 | @Min(1) | 故事书ID | 123 |
| content | String | 是 | @NotBlank | 故事内容 | "从前有一个..." |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "quizId": 456,
    "questions": [
      {
        "id": 1,
        "question": "故事的主人公是谁？",
        "options": ["A. 小红", "B. 小明", "C. 小刚", "D. 小丽"],
        "correctAnswer": "A",
        "explanation": "根据故事内容，主人公是小红"
      }
    ]
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| BOOK-QUIZ-GEN-001 | 正常生成Quiz | 返回生成的Quiz数据 | P1 |
| BOOK-QUIZ-GEN-002 | 故事书不存在 | 返回故事书不存在错误 | P1 |
| BOOK-QUIZ-GEN-003 | 内容为空 | 返回参数错误 | P1 |
| BOOK-QUIZ-GEN-004 | 内容过长 | 返回内容长度超限错误 | P2 |

---

#### 2.4.4 异步生成故事书的quiz
**接口地址**: `POST /book/{bookId}/quiz/generateAsync`  
**接口描述**: 异步生成故事书的quiz  
**请求方式**: POST  
**是否需要认证**: 是  
**控制器**: BookController.generateStoryQuizAsync()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| bookId | Long | 是 | @Min(1) | 故事书ID | 123 |
| content | String | 是 | @NotBlank | 故事内容 | "从前有一个..." |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "taskId": "task_abc123def456"
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| BOOK-QUIZ-ASYNC-001 | 正常异步生成 | 返回任务ID | P1 |
| BOOK-QUIZ-ASYNC-002 | 故事书不存在 | 返回故事书不存在错误 | P1 |
| BOOK-QUIZ-ASYNC-003 | 内容为空 | 返回参数错误 | P1 |

---

#### 2.4.5 查询故事quiz生成任务状态
**接口地址**: `GET /book/{bookId}/quiz/{taskId}/status`  
**接口描述**: 查询故事quiz生成任务状态  
**请求方式**: GET  
**是否需要认证**: 是  
**控制器**: BookController.getStoryQuizTaskStatus()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| bookId | Long | 是 | @Min(1) | 故事书ID | 123 |
| taskId | String | 是 | @NotBlank | 任务ID | "task_abc123def456" |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "status": "COMPLETED",
    "result": {
      "quizId": 456,
      "questions": [...]
    }
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| BOOK-QUIZ-STATUS-001 | 正常查询状态 | 返回任务状态 | P1 |
| BOOK-QUIZ-STATUS-002 | 任务不存在 | 返回任务不存在错误 | P1 |
| BOOK-QUIZ-STATUS-003 | 任务已完成 | 返回完成状态和结果 | P1 |

---

#### 2.4.6 保存故事书的quiz
**接口地址**: `POST /book/{bookId}/quiz`  
**接口描述**: 保存故事书的quiz  
**请求方式**: POST  
**是否需要认证**: 是  
**控制器**: BookController.saveBookQuiz()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| bookId | Long | 是 | @Min(1) | 故事书ID | 123 |
| content | String | 是 | @NotBlank | 测验内容 | "{\"questions\":[...]}" |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "quizId": 456,
    "saved": true
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| BOOK-QUIZ-SAVE-001 | 正常保存Quiz | 返回保存成功 | P1 |
| BOOK-QUIZ-SAVE-002 | 故事书不存在 | 返回故事书不存在错误 | P1 |
| BOOK-QUIZ-SAVE-003 | 内容格式错误 | 返回格式错误 | P1 |

---

#### 2.4.7 查询故事书的quiz
**接口地址**: `GET /book/{bookId}/quiz`  
**接口描述**: 查询故事书的quiz  
**请求方式**: GET  
**是否需要认证**: 否 (@PublicApi)  
**控制器**: BookController.getBookQuiz()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| bookId | Long | 是 | @Min(1) | 故事书ID | 123 |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "quizId": 456,
    "questions": [
      {
        "id": 1,
        "question": "故事的主人公是谁？",
        "options": ["A. 小红", "B. 小明", "C. 小刚", "D. 小丽"],
        "correctAnswer": "A",
        "explanation": "根据故事内容，主人公是小红"
      }
    ]
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| BOOK-QUIZ-GET-001 | 正常查询Quiz | 返回Quiz数据 | P1 |
| BOOK-QUIZ-GET-002 | 故事书不存在 | 返回故事书不存在错误 | P1 |
| BOOK-QUIZ-GET-003 | Quiz不存在 | 返回Quiz不存在错误 | P1 |

---

#### 2.4.8 上传故事书quiz图片
**接口地址**: `POST /book/quiz/uploadImageBase64`  
**接口描述**: 上传故事书quiz图片，图片格式为base64  
**请求方式**: POST  
**是否需要认证**: 是  
**控制器**: BookController.uploadImageBase64()  

**请求参数**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| imageBase64 | String | 是 | @NotBlank | base64格式的图片数据 | "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..." |

**响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "url": "https://s3.amazonaws.com/bucket/quiz/image_abc123.png"
  }
}
```

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| BOOK-QUIZ-IMG-001 | 正常上传图片 | 返回图片URL | P1 |
| BOOK-QUIZ-IMG-002 | base64格式错误 | 返回格式错误 | P1 |
| BOOK-QUIZ-IMG-003 | 图片过大 | 返回文件大小超限错误 | P1 |
| BOOK-QUIZ-IMG-004 | 非图片格式 | 返回文件类型错误 | P1 |

---

## 3. 修改接口测试

### 3.1 书籍推荐相关接口 (BookController)

#### 3.1.1 推荐体验课与故事书
**接口地址**: `GET /book/recommend/bookAndCourse`  
**接口描述**: 推荐体验课与故事书，新增A/B测试支持  
**请求方式**: GET  
**是否需要认证**: 否 (@PublicApi)  
**控制器**: BookController.recommendBookAndCourse()  

**请求参数（新增/变更）**:
| 参数名 | 类型 | 必填 | 验证规则 | 默认值 | 说明 | 示例 |
|--------|------|------|----------|--------|------|------|
| abTest | Boolean | 否 | - | false | A/B测试标识 | true |

**原有参数保持不变**:
| 参数名 | 类型 | 必填 | 验证规则 | 默认值 | 说明 | 示例 |
|--------|------|------|----------|--------|------|------|
| courseNum | Int | 否 | @Min(1) @Max(10) | 3 | 课程数量 | 3 |
| englishLevel | Int | 否 | @Min(-1) @Max(10) | -1 | 英语等级 | 1 |
| learningPurposes | String | 否 | - | "" | 学习目的 | "1,3" |
| age | Int | 否 | @Min(0) @Max(100) | null | 年龄 | 8 |
| translateLanguage | String | 否 | - | null | 翻译语言 | "zh" |

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| BOOK-REC-001 | 正常推荐（abTest=false） | 返回推荐结果 | P1 |
| BOOK-REC-002 | A/B测试推荐（abTest=true） | 返回A/B测试推荐结果 | P1 |
| BOOK-REC-003 | 原有参数组合测试 | 返回推荐结果 | P1 |
| BOOK-REC-004 | A/B测试+年龄筛选 | 返回A/B测试推荐结果 | P2 |

---

### 3.2 管理后台相关接口 (AdminController)

#### 3.2.1 获取体验课推荐规则
**接口地址**: `GET /course/recommend/spelRules`  
**接口描述**: 获取体验课程推荐SpEL表达式规则，新增A/B测试支持  
**请求方式**: GET  
**是否需要认证**: 是 (@AdminApi)  
**控制器**: AdminController.getCourseRecommendSpelRules()  

**请求参数（新增/变更）**:
| 参数名 | 类型 | 必填 | 验证规则 | 默认值 | 说明 | 示例 |
|--------|------|------|----------|--------|------|------|
| abTest | Boolean | 否 | - | false | A/B测试标识 | true |

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| ADMIN-RULES-GET-001 | 正常获取规则（abTest=false） | 返回推荐规则 | P1 |
| ADMIN-RULES-GET-002 | A/B测试规则（abTest=true） | 返回A/B测试规则 | P1 |

---

#### 3.2.2 设置体验课推荐规则
**接口地址**: `POST /course/recommend/spelRules`  
**接口描述**: 设置体验课程推荐SpEL表达式规则，新增A/B测试支持  
**请求方式**: POST  
**是否需要认证**: 是 (@AdminApi)  
**控制器**: AdminController.updateCourseRecommendSpelRules()  

**请求参数（新增/变更）**:
| 参数名 | 类型 | 必填 | 验证规则 | 默认值 | 说明 | 示例 |
|--------|------|------|----------|--------|------|------|
| abTest | Boolean | 否 | - | false | A/B测试标识 | true |

**原有参数保持不变**:
| 参数名 | 类型 | 必填 | 验证规则 | 说明 | 示例 |
|--------|------|------|----------|------|------|
| rules | CourseRecommendRulesReq | 是 | @NotNull | 推荐规则 | {...} |

**测试用例**:
| 用例ID | 测试场景 | 预期结果 | 优先级 |
|--------|----------|----------|--------|
| ADMIN-RULES-SET-001 | 正常设置规则（abTest=false） | 返回设置成功 | P1 |
| ADMIN-RULES-SET-002 | A/B测试规则设置（abTest=true） | 返回设置成功 | P1 |
| ADMIN-RULES-SET-003 | 规则格式错误 | 返回格式错误 | P1 |

---

## 4. 数据库测试

### 4.1 新增表结构测试
| 表名 | 测试场景 | 预期结果 | 优先级 |
|------|----------|----------|--------|
| donate_expend | 创建支出记录 | 记录成功创建 | P1 |
| donate_expend | 更新支出记录 | 记录成功更新 | P1 |
| donate_expend | 查询支出记录 | 返回正确数据 | P1 |
| books_multilingual | 更新首页语音字段 | 字段更新成功 | P1 |

### 4.2 数据完整性测试
| 测试场景 | 预期结果 | 优先级 |
|----------|----------|--------|
| 外键约束测试 | 符合约束规则 | P1 |
| 索引性能测试 | 查询性能良好 | P2 |
| 数据迁移测试 | 数据迁移成功 | P1 |

---

## 5. 性能测试

### 5.1 接口性能测试
| 接口 | 并发用户数 | 响应时间要求 | 吞吐量要求 | 优先级 |
|------|------------|---------------|------------|--------|
| 获取活动列表 | 100 | <500ms | >200 req/s | P1 |
| 支出记录查询 | 50 | <300ms | >100 req/s | P1 |
| Quiz生成 | 10 | <5s | >10 req/s | P2 |
| 课程资源查询 | 200 | <200ms | >500 req/s | P1 |

### 5.2 数据库性能测试
| 测试场景 | 预期结果 | 优先级 |
|----------|----------|--------|
| 大量数据查询 | 响应时间<1s | P1 |
| 并发写入测试 | 无数据丢失 | P1 |
| 索引效率测试 | 查询效率提升 | P2 |

---

## 6. 安全测试

### 6.1 认证授权测试
| 测试场景 | 预期结果 | 优先级 |
|----------|----------|--------|
| 未认证访问受保护接口 | 返回401错误 | P1 |
| 权限不足访问管理接口 | 返回403错误 | P1 |
| Token过期测试 | 返回401错误 | P1 |

### 6.2 输入验证测试
| 测试场景 | 预期结果 | 优先级 |
|----------|----------|--------|
| SQL注入测试 | 阻止恶意输入 | P1 |
| XSS攻击测试 | 过滤恶意脚本 | P1 |
| 文件上传安全测试 | 限制文件类型和大小 | P1 |

---

## 7. 兼容性测试

### 7.1 浏览器兼容性
| 浏览器 | 版本 | 测试状态 | 优先级 |
|--------|------|----------|--------|
| Chrome | 最新版 | 待测试 | P1 |
| Firefox | 最新版 | 待测试 | P1 |
| Safari | 最新版 | 待测试 | P2 |

### 7.2 移动端兼容性
| 设备类型 | 测试状态 | 优先级 |
|----------|----------|--------|
| iOS Safari | 待测试 | P1 |
| Android Chrome | 待测试 | P1 |

---

## 8. 测试环境配置

### 8.1 测试环境信息
| 环境 | URL | 数据库 | 状态 |
|------|-----|--------|------|
| 开发环境 | [待填写] | [待填写] | 可用 |
| 测试环境 | [待填写] | [待填写] | 可用 |
| 预生产环境 | [待填写] | [待填写] | 可用 |

### 8.2 测试数据准备
| 数据类型 | 数量 | 说明 |
|----------|------|------|
| 用户数据 | 1000 | 包含不同角色和权限 |
| 故事书数据 | 500 | 包含多语言版本 |
| 课程数据 | 200 | 包含不同级别 |
| 活动数据 | 50 | 包含不同状态 |

---

## 9. 测试执行计划

### 9.1 测试阶段安排
| 阶段 | 时间 | 负责人 | 状态 |
|------|------|--------|------|
| 环境准备 | 1天 | [待填写] | 待开始 |
| 单元测试 | 2天 | [待填写] | 待开始 |
| 接口测试 | 3天 | [待填写] | 待开始 |
| 集成测试 | 2天 | [待填写] | 待开始 |
| 性能测试 | 1天 | [待填写] | 待开始 |
| 安全测试 | 1天 | [待填写] | 待开始 |

### 9.2 测试优先级
- **P0**: 阻塞性问题，必须修复
- **P1**: 高优先级，影响核心功能
- **P2**: 中优先级，影响用户体验
- **P3**: 低优先级，优化建议

---

## 10. 风险评估

### 10.1 技术风险
| 风险项 | 影响程度 | 发生概率 | 应对措施 |
|--------|----------|----------|----------|
| 数据库性能问题 | 高 | 中 | 优化查询和索引 |
| 第三方服务依赖 | 中 | 中 | 增加降级方案 |
| 并发访问压力 | 高 | 低 | 压力测试验证 |

### 10.2 业务风险
| 风险项 | 影响程度 | 发生概率 | 应对措施 |
|--------|----------|----------|----------|
| 数据迁移失败 | 高 | 低 | 备份和回滚方案 |
| 用户数据丢失 | 高 | 低 | 数据备份策略 |
| 服务不可用 | 中 | 中 | 监控和告警 |

---

## 11. 测试工具和环境

### 11.1 测试工具
| 工具类型 | 工具名称 | 版本 | 用途 |
|----------|----------|------|------|
| 接口测试 | Postman | 最新版 | API测试 |
| 性能测试 | JMeter | 5.5 | 压力测试 |
| 数据库 | MySQL | 8.0 | 数据验证 |
| 监控 | Grafana | 最新版 | 性能监控 |

### 11.2 测试环境要求
- **服务器配置**: 4核8G内存，100G硬盘
- **网络环境**: 稳定的网络连接
- **数据库**: MySQL 8.0+
- **Java版本**: JDK 11+

---

## 12. 测试报告模板

### 12.1 测试执行结果
| 测试类型 | 用例总数 | 通过数 | 失败数 | 通过率 |
|----------|----------|--------|--------|--------|
| 新增接口测试 | 55 | - | - | - |
| 修改接口测试 | 9 | - | - | - |
| 数据库测试 | 8 | - | - | - |
| 性能测试 | 4 | - | - | - |
| 安全测试 | 6 | - | - | - |
| 兼容性测试 | 3 | - | - | - |
| **总计** | **85** | - | - | - |

### 12.2 缺陷统计
| 严重级别 | 数量 | 状态 |
|----------|------|------|
| P0 | 0 | - |
| P1 | 0 | - |
| P2 | 0 | - |
| P3 | 0 | - |

### 12.3 测试结论
- [ ] 所有P0和P1级别测试用例通过
- [ ] 性能指标满足要求
- [ ] 安全测试无高危漏洞
- [ ] 兼容性测试通过
- [ ] 可以发布到生产环境

---

## 13. 附录

### 13.1 接口变更清单
**新增接口（14个）**:
1. `GET /activity/gacha/list` - 获取扭蛋活动列表
2. `POST /expend/update-remark` - 更新支出记录备注
3. `GET /expend/list` - 分页查询支出记录列表
4. `PUT /class/{classId}/groups` - 更新班级学生默认分组
5. `GET /lesson/resource/normalCourse` - Normal课程资源列表
6. `GET /lesson/resource/quiz` - 测验列表
7. `POST /book/{bookId}/indexAudio/{language}` - 上传故事书首页语音
8. `GET /book/{bookId}/indexAudio/{language}` - 查询故事书首页语音
9. `POST /book/{bookId}/quiz/generate` - 生成故事书的quiz
10. `POST /book/{bookId}/quiz/generateAsync` - 异步生成故事书的quiz
11. `GET /book/{bookId}/quiz/{taskId}/status` - 查询故事quiz生成任务状态
12. `POST /book/{bookId}/quiz` - 保存故事书的quiz
13. `GET /book/{bookId}/quiz` - 查询故事书的quiz
14. `POST /book/quiz/uploadImageBase64` - 上传故事书quiz图片

**修改接口（3个）**:
1. `GET /book/recommend/bookAndCourse` - 新增 `abTest` 参数
2. `GET /course/recommend/spelRules` - 新增 `abTest` 参数
3. `POST /course/recommend/spelRules` - 新增 `abTest` 参数

### 13.2 数据库变更清单
- 新增 `donate_expend` 表
- 修改 `books_multilingual` 表，增加首页语音字段
- 相关表结构优化以支持A/B测试

### 13.3 测试数据模板
```json
{
  "testUser": {
    "userId": 12345,
    "email": "test@example.com",
    "role": "USER"
  },
  "testBook": {
    "bookId": 123,
    "title": "测试故事书",
    "language": "zh"
  },
  "testClass": {
    "classId": 456,
    "name": "测试班级",
    "studentCount": 30
  }
}
```

---

**文档版本**: v1.0  
**最后更新**: 2025年1月  
**文档状态**: 待审核