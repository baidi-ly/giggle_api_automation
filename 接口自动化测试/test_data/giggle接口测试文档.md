# 接口测试文档 v1.20.0

## 概述

本文档基于 `develop` 分支和 `release/1.20.0` 分支的差异分析，详细记录了 v1.20.0 版本中新增和修改的API接口。

## 分支对比信息

- **对比分支**: develop vs release/1.20.0
- **变更统计**: 59个文件变更，新增3307行，删除409行
- **主要变更**: 新增多个API接口，包括故事书评价、学校测验报告、AI翻译、捐赠支出管理等功能

## 新增API接口

### 1. 故事书相关接口 (BookController)

#### 1.1 上传故事书首页语音
- **接口路径**: `POST /book/{bookId}/indexAudio/{language}`
- **功能描述**: 上传并保存故事书首页语音文件
- **请求参数**:
  - `bookId` (Long): 故事书ID
  - `language` (String): 语言代码，如 "zh"
  - `audioFile` (MultipartFile): 音频文件
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "s3Key": "books/index-audio/123_zh.mp3"
  }
}
```

#### 1.2 查询故事书首页语音
- **接口路径**: `GET /book/{bookId}/indexAudio/{language}`
- **功能描述**: 查询故事书首页语音文件
- **请求参数**:
  - `bookId` (Long): 故事书ID
  - `language` (String): 语言代码
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "indexAudioKey": "books/index-audio/123_zh.mp3"
  }
}
```

#### 1.3 检查故事书阅读状态
- **接口路径**: `GET /book/{bookId}/reading-status`
- **功能描述**: 检查孩子是否读过某本故事书
- **请求参数**:
  - `bookId` (Long): 故事书ID
  - `kidId` (Long): 孩子ID
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "hasRead": true,
    "readTime": "2024-01-15 10:30:00"
  }
}
```

#### 1.4 保存故事书评价
- **接口路径**: `POST /book/rating`
- **功能描述**: 保存用户对故事书的评价
- **请求体**:
```json
{
  "bookId": 123,
  "kidId": 456,
  "rating": 3
}
```
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "id": 789,
    "rating": 3
  }
}
```

#### 1.5 获取评价反馈选项配置
- **接口路径**: `GET /book/rating/feedback-options`
- **功能描述**: 获取评价反馈选项配置（公开接口）
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "options": [
      {"id": 1, "text": "很有趣"},
      {"id": 2, "text": "很有教育意义"}
    ]
  }
}
```

#### 1.6 更新评价反馈选项配置
- **接口路径**: `POST /book/rating/feedback-options`
- **功能描述**: 更新评价反馈选项配置
- **请求体**:
```json
{
  "optionsJson": "{\"options\":[{\"id\":1,\"text\":\"很有趣\"}]}"
}
```

#### 1.7 推荐书籍接口增强
- **接口路径**: `GET /book/recommend`
- **新增参数**:
  - `abTest` (Boolean): A/B测试标识，默认false

### 2. 学校系统接口 (SchoolController)

#### 2.1 获取班级学生默认分组详情
- **接口路径**: `GET /school/class/{classId}/groups`
- **功能描述**: 获取班级学生的默认分组信息
- **请求参数**:
  - `classId` (Long): 班级ID
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": [
    {
      "groupId": 1,
      "groupName": "第一组",
      "students": [
        {"studentId": 1, "studentName": "张三"},
        {"studentId": 2, "studentName": "李四"}
      ]
    }
  ]
}
```

#### 2.2 更新班级学生默认分组
- **接口路径**: `PUT /school/class/{classId}/groups`
- **功能描述**: 更新班级学生的默认分组
- **请求体**:
```json
{
  "groups": [
    {
      "groupId": 1,
      "groupName": "第一组",
      "studentIds": [1, 2, 3]
    }
  ]
}
```

#### 2.3 更新课堂学生默认分组
- **接口路径**: `PUT /school/lesson/{lessonId}/groups`
- **功能描述**: 更新课堂学生的默认分组
- **请求体**: 同班级分组更新

#### 2.4 测验报告列表
- **接口路径**: `GET /school/lesson/{lessonId}/quiz/report/list`
- **功能描述**: 获取课堂测验报告列表
- **请求参数**:
  - `lessonId` (Long): 课堂ID
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": [
    {
      "id": 1,
      "lessonId": 123,
      "lessonResourceId": 456,
      "name": "第一单元测验报告",
      "createTime": "2024-01-15 10:30:00"
    }
  ]
}
```

#### 2.5 测验结果上报
- **接口路径**: `POST /school/lesson/{lessonId}/quiz/{quizId}/report`
- **功能描述**: 上报学生测验结果
- **请求体**:
```json
{
  "studentId": 1,
  "resourceId": 456,
  "answers": [
    {
      "instructionalDomain": "阅读理解",
      "questionSeqNo": 1,
      "questionType": "选择题",
      "score": 2,
      "answerData": "{\"selected\":\"A\"}",
      "answerTime": "2024-01-15 10:30:00",
      "duration": 30
    }
  ]
}
```

#### 2.6 测验报告详情
- **接口路径**: `GET /school/lesson/{lessonId}/quiz/report/{lessonReportId}`
- **功能描述**: 获取测验报告详细数据
- **请求参数**:
  - `lessonId` (Long): 课堂ID
  - `lessonReportId` (Long): 报告ID
  - `page` (Int): 页码，默认0
  - `size` (Int): 每页数量，默认20
  - `all` (Boolean): 是否获取全部数据
  - `students` (String): 学生ID列表，逗号分隔
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "id": 1,
    "lessonId": 123,
    "lessonResourceId": 456,
    "name": "第一单元测验报告",
    "createTime": "2024-01-15 10:30:00",
    "contents": [
      {
        "studentId": 1,
        "studentName": "张三",
        "answers": [
          {
            "id": 1,
            "instructionalDomain": "阅读理解",
            "questionSeqNo": 1,
            "questionType": "选择题",
            "score": 2,
            "answerData": "{\"selected\":\"A\"}",
            "answerTime": "2024-01-15 10:30:00",
            "duration": 30
          }
        ]
      }
    ],
    "totalElements": 25,
    "totalPages": 2,
    "number": 0,
    "size": 20,
    "first": true,
    "last": false
  }
}
```

### 3. AI相关接口 (AIController)

#### 3.1 文本翻译
- **接口路径**: `POST /ai/translate`
- **功能描述**: 翻译文本内容（公开接口）
- **请求参数**:
  - `text` (String): 要翻译的文本
  - `targetLanguageCode` (String): 目标语言代码，如 "zh"
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "translatedText": "翻译后的文本"
  }
}
```

### 4. 捐赠订单接口 (DonateOrderController)

#### 4.1 更新支出记录
- **接口路径**: `POST /expend/update-remark`
- **功能描述**: 更新支出记录的备注、详情URL和分类（公开接口）
- **请求参数**:
  - `transactionId` (String): 交易ID
  - `remark` (String): 备注
  - `detailUrl` (String): 详情URL
  - `category` (String): 分类
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": "支出记录已更新"
}
```

#### 4.2 分页查询支出记录列表
- **接口路径**: `GET /expend/list`
- **功能描述**: 分页查询支出记录列表（公开接口）
- **请求参数**:
  - `page` (Int): 页码，默认0
  - `size` (Int): 每页数量，默认20，最大100
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "content": [
      {
        "id": 1,
        "transactionId": "0x123...",
        "transactionTime": "2024-01-15 10:30:00",
        "currency": "USDT",
        "amount": 100.00,
        "networkType": "ETH",
        "toAddress": "0x456...",
        "remark": "购买教材",
        "detailUrl": "https://example.com",
        "category": "教育支出"
      }
    ],
    "totalElements": 100,
    "totalPages": 5,
    "number": 0,
    "size": 20
  }
}
```

### 5. 扭蛋活动接口 (GachaActivityController)

#### 5.1 获取当前正在进行的扭蛋活动
- **接口路径**: `GET /activity/gacha/list`
- **功能描述**: 获取当前正在进行的扭蛋活动列表
- **请求参数**:
  - `language` (String): 语言代码
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": [
    {
      "id": 1,
      "name": "春节扭蛋活动",
      "startTime": "2024-01-01 00:00:00",
      "endTime": "2024-01-31 23:59:59",
      "status": "ACTIVE"
    }
  ]
}
```

### 6. 游戏相关接口 (GameController)

#### 6.1 查询故事书Tab是否显示
- **接口路径**: `GET /game/tab-storybook/visible`
- **功能描述**: 查询故事书Tab是否显示（公开接口）
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "visible": true
  }
}
```

#### 6.2 课程完成接口增强
- **接口路径**: `POST /game/course/complete`
- **功能增强**: 增加完课抽奖次数功能

### 7. 管理后台接口 (AdminController)

#### 7.1 设置故事书翻译并发阈值
- **接口路径**: `POST /admin/book-translation/concurrent-threshold`
- **功能描述**: 设置故事书翻译的并发阈值
- **请求参数**:
  - `threshold` (Int): 并发阈值
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": "设置成功"
}
```

#### 7.2 设置故事书Tab显示状态
- **接口路径**: `POST /admin/tab-storybook/visible`
- **功能描述**: 设置故事书Tab的显示状态
- **请求参数**:
  - `visible` (Boolean): 是否显示
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": "设置成功"
}
```

#### 7.3 触发作者排名计算
- **接口路径**: `POST /admin/author-ranking/calculate`
- **功能描述**: 手动触发作者排名计算任务
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": "任务已触发"
}
```

#### 7.4 获取教学维度列表
- **接口路径**: `GET /admin/instructional-domain/list`
- **功能描述**: 获取所有教学维度标签列表
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": [
    {
      "id": 1,
      "name": "阅读理解"
    },
    {
      "id": 2,
      "name": "词汇学习"
    }
  ]
}
```

#### 7.5 创建教学维度
- **接口路径**: `POST /admin/instructional-domain/create`
- **功能描述**: 创建新的教学维度标签
- **请求体**:
```json
{
  "name": "语法学习"
}
```
- **响应示例**:
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "id": 3,
    "name": "语法学习"
  }
}
```

#### 7.6 课程推荐规则管理
- **接口路径**: `GET /admin/course-recommend-spel-rules`
- **功能描述**: 获取课程推荐SPEL规则
- **接口路径**: `POST /admin/course-recommend-spel-rules`
- **功能描述**: 更新课程推荐SPEL规则

## 新增错误码

### RestErrorCode 新增错误码
- `SCHOOL_CLASS_STUDENT_NOT_BELONG` (100139): 学生不属于该班级
- `SCHOOL_LESSON_QUIZ_REPORT_NOT_FOUND` (100140): 课堂测验报告未找到
- `SCHOOL_REPORT_NOT_FOUND` (100141): 学校报告未找到
- `SCHOOL_REPORT_NOT_BELONG` (100142): 学校报告不属于该课堂
- `QUIZ_NOT_FOUND` (100143): 测验未找到
- `QUIZ_QUESTION_COUNT_MISMATCH` (100144): 测验问题数量不匹配
- `QUIZ_DATA_FORMAT_ERROR` (100145): 测验数据格式错误

## 配置变更

### 新增配置项

#### CCBot 通知服务配置
```yaml
# 开发环境配置 (application-dev.yml)
ccbot:
  base-url: http://internal-gigle-giggle-ai-bot-alb-2044456368.ap-northeast-1.elb.amazonaws.com
  api-token: 3b6f0f1f-6c28-4e0f-9c30-7e1db5c2a4e1
  story-group-id: "fc7f7f9ade5b422b889d7644598c8688"
```

### 新增服务

#### CCBotNotificationService
- **功能**: 向CCBot发送故事书评价相关的通知消息
- **主要方法**:
  - `sendLowSatisfactionNotification()`: 发送低满意度评价通知
- **用途**: 当用户对故事书给出低评价时，自动通知相关团队

### 工具类增强

#### TokenUtil 增强
- **新增方法**:
  - `getPermanentToken()`: 根据作用域生成永久token
  - `validateToken()`: 验证token并返回用户ID和作用域信息
- **用途**: 支持基于作用域的永久token生成和验证

### 资源文件更新

#### 国家代码文件更新
- **文件**: `country_calling_codes.json`
- **新增**: 澳门地区代码 (+853)
- **详细信息**:
  - 国家代码: MO
  - 区号: +853
  - 国家名称: Macau
  - 本地名称: 澳門
  - 语言: zh-Hant

## 数据库变更

### 新增表结构

#### 1. 故事书评价表 (book_rating)
```sql
CREATE TABLE IF NOT EXISTS `book_rating` (
    `id` BIGINT NOT NULL COMMENT '评价记录ID',
    `user_id` BIGINT NOT NULL COMMENT '用户ID',
    `kid_id` BIGINT NOT NULL COMMENT '孩子ID',
    `book_id` BIGINT NOT NULL COMMENT '故事书ID',
    `rating` TINYINT NOT NULL COMMENT '星级评价：1=差，2=一般，3=好',
    `db_create_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `db_modify_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (`id`),
    KEY `idx_user_id` (`user_id`),
    KEY `idx_kid_id` (`kid_id`),
    KEY `idx_book_id` (`book_id`),
    KEY `idx_rating` (`rating`),
    KEY `idx_db_create_time` (`db_create_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='故事书评价表';
```

#### 2. 捐赠支出表 (donate_expend)
```sql
CREATE TABLE IF NOT EXISTS `donate_expend` (
    `id` BIGINT NOT NULL COMMENT '支出记录ID',
    `transaction_id` VARCHAR(66) NOT NULL COMMENT '交易哈希',
    `transaction_time` DATETIME NOT NULL COMMENT '交易时间',
    `currency` VARCHAR(10) NOT NULL COMMENT '币种',
    `amount` DECIMAL(20,8) NOT NULL COMMENT '数量',
    `network_type` VARCHAR(20) NOT NULL COMMENT '网络类型(如ETH、BSC等)',
    `to_address` VARCHAR(42) NOT NULL COMMENT '转入地址',
    `remark` TEXT NULL COMMENT '备注',
    `detail_url` VARCHAR(500) NULL COMMENT '详情URL',
    `category` VARCHAR(100) NULL COMMENT '分类',
    `db_create_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `db_modify_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_transaction_id` (`transaction_id`),
    KEY `idx_transaction_time` (`transaction_time`),
    KEY `idx_db_create_time` (`db_create_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='捐赠支出表';
```

#### 3. 教学维度标签表 (quiz_instructional_domain)
```sql
CREATE TABLE `quiz_instructional_domain` (
    `id`             BIGINT      NOT NULL COMMENT 'ID',
    `name`           VARCHAR(64) NOT NULL DEFAULT '' COMMENT '教学维度标签名称',
    `db_create_time` DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `db_modify_time` DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (`id`),
    INDEX            `idx_name` (`name`)
) ENGINE = InnoDB CHARSET = utf8mb4 COLLATE utf8mb4_unicode_ci COMMENT '教学维度标签表';
```

#### 4. 课堂测验报告表 (school_lesson_report)
```sql
CREATE TABLE `school_lesson_report` (
    `id`                 BIGINT      NOT NULL COMMENT 'ID',
    `lesson_id`          BIGINT      NOT NULL DEFAULT 0 COMMENT '课堂ID',
    `lesson_resource_id` BIGINT      NOT NULL DEFAULT 0 COMMENT '课堂资源ID',
    `name`               VARCHAR(64) NOT NULL DEFAULT '' COMMENT '课堂测验报告名称',
    `db_create_time`     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `db_modify_time`     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (`id`),
    INDEX                `idx_lesson_id` (`lesson_id`),
    INDEX                `idx_lesson_resource_id` (`lesson_resource_id`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci COMMENT = '课堂报告表';
```

#### 5. 课堂测验报告记录表 (school_lesson_quiz_answer)
```sql
CREATE TABLE `school_lesson_quiz_answer` (
    `id`                   BIGINT      NOT NULL COMMENT 'ID',
    `lesson_report_id`     BIGINT      NOT NULL DEFAULT 0 COMMENT '报告ID',
    `student_id`           BIGINT      NOT NULL DEFAULT 0 COMMENT '学生ID',
    `quiz_id`              BIGINT      NOT NULL DEFAULT 0 COMMENT '测验ID',
    `instructional_domain` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '教学维度',
    `question_seq_no`      INT         NOT NULL DEFAULT 1 COMMENT '问题序号',
    `question_type`        VARCHAR(32) NOT NULL DEFAULT '' COMMENT '题型',
    `score`                TINYINT     NOT NULL DEFAULT 0 COMMENT '得分: 0-2分',
    `answer_data`          JSON NULL DEFAULT NULL COMMENT '答案详情',
    `answer_time`          DATETIME    NULL DEFAULT NULL COMMENT '答题时间',
    `duration`             INT NULL DEFAULT 0 COMMENT '答题时长(秒)',
    `db_create_time`       DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `db_modify_time`       DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (`id`),
    INDEX                  `idx_report_student` (`lesson_report_id`, `student_id`),
    INDEX                  `idx_quiz` (`quiz_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='学生答题记录表';
```

### 表结构修改

#### 1. 故事书多语言表 (books_multilingual)
- 新增字段: `index_audio_key` VARCHAR(500) - 故事书首页语音的S3 Key

#### 2. 课堂表 (school_lesson)
- 新增字段: `voice_recognition` TINYINT(1) - 是否开启语音识别：0-否，1-是

#### 3. 课堂分组表 (school_lesson_student_group)
- 新增字段: `class_id` BIGINT - 班级ID
- 修改字段: `lesson_id` 允许为NULL，默认值为0

## 测试建议

### 1. 功能测试
- 测试所有新增接口的基本功能
- 验证请求参数验证逻辑
- 测试异常情况处理

### 2. 权限测试
- 验证需要登录的接口的权限控制
- 测试公开接口的访问权限
- 验证用户身份验证逻辑

### 3. 数据完整性测试
- 测试数据库约束和索引
- 验证外键关系
- 测试数据一致性

### 4. 性能测试
- 测试分页查询接口的性能
- 验证大数据量下的响应时间
- 测试并发访问情况

### 5. 兼容性测试
- 测试与现有接口的兼容性
- 验证数据库迁移的正确性
- 测试向后兼容性

## 注意事项

1. **数据库迁移**: 部署前需要执行 `base.v1.20.sql` 迁移脚本
2. **权限控制**: 部分接口需要用户登录，部分为公开接口
3. **文件上传**: 故事书首页语音上传接口需要支持音频文件格式
4. **分页查询**: 支出记录列表接口有分页限制，最大每页100条
5. **JSON数据**: 测验答案详情使用JSON格式存储
6. **时间格式**: 所有时间字段使用 "yyyy-MM-dd HH:mm:ss" 格式

## 版本信息

- **文档版本**: v1.20.0
- **生成时间**: 2024年1月
- **对比分支**: develop vs release/1.20.0
- **变更文件数**: 59个文件
- **新增代码行数**: 3307行
- **删除代码行数**: 409行

## 功能模块总结

### 主要新增功能模块：

1. **故事书评价系统** - 支持用户对故事书进行星级评价，包含低满意度通知机制
2. **学校测验报告系统** - 完整的课堂测验数据收集和分析功能
3. **AI翻译服务** - 新增文本翻译API接口
4. **捐赠支出管理** - 区块链交易支出记录管理
5. **扭蛋活动增强** - 新增活动列表查询接口
6. **游戏功能优化** - 完课抽奖、Tab显示控制等功能
7. **管理后台增强** - 教学维度管理、翻译并发控制、作者排名计算等
8. **Token系统增强** - 支持基于作用域的永久token生成和验证
9. **CCBot通知服务** - 自动通知低满意度评价
10. **地区支持扩展** - 新增澳门地区支持

### 新增API接口统计：
- **故事书相关**: 7个新接口
- **学校系统**: 6个新接口
- **AI服务**: 1个新接口
- **捐赠管理**: 2个新接口
- **扭蛋活动**: 1个新接口
- **游戏功能**: 1个新接口
- **管理后台**: 6个新接口
- **总计**: 24个新增API接口

### 数据库变更统计：
- **新增表**: 5个表
- **修改表**: 3个表
- **新增字段**: 8个字段
- **新增索引**: 多个索引优化
