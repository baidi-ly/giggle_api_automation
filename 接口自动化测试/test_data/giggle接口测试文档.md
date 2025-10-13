# 接口测试文档 v1.20.0

## 1. 版本概述

**版本号**: v1.20.0  
**发布日期**: 2025年10月  
**测试环境**: [待填写]  
**生产环境**: [待填写]

### 1.1 主要功能更新
- **分支对比结果**: develop 与 release/1.20.0 存在接口层面的新增与修改
- **数据库变更**: 数据库迁移文件 `base.v1.20.sql`
- **接口状态**: 新增接口与参数调整如下文所述

### 1.2 对比范围说明
- **基础分支**: develop（最新）
- **目标分支**: release/1.20.0（最新）
- 对比方式：基于 Controller 注解及方法签名差异

---

## 2. 新增接口测试

### 2.1 扭蛋活动-获取活动列表
- **接口描述**: 获取当前正在进行的扭蛋活动
- **请求方法**: GET
- **请求路径**: `/activity/gacha/list`
- **鉴权**: 需要登录（与同模块接口一致）
- **请求参数**:
  - `language` (query, string, 可选): 语言代码
- **成功响应**: 200，返回活动列表数据结构（`GachaActivityResponse[]`）
- **所在类**: `com.giggleacademy.app.api.controller.GachaActivityController`

### 2.2 故事书首页语音-上传
- **接口描述**: 上传并保存故事书首页语音
- **请求方法**: POST
- **请求路径**: `/book/{bookId}/indexAudio/{language}`
- **鉴权**: 需要登录（与书籍管理相关接口一致）
- **请求参数**:
  - `bookId` (path, long, 必填)
  - `language` (path, string, 必填)
  - `audioFile` (form-data, file, 必填)
- **成功响应**: 200，返回 `{ "s3Key": "..." }`
- **所在类**: `com.giggleacademy.app.api.controller.BookController`

### 2.3 故事书首页语音-查询
- **接口描述**: 查询故事书首页语音的资源 Key
- **请求方法**: GET
- **请求路径**: `/book/{bookId}/indexAudio/{language}`
- **鉴权**: PublicApi（公开）
- **请求参数**:
  - `bookId` (path, long, 必填)
  - `language` (path, string, 必填)
- **成功响应**: 200，返回 `{ "indexAudioKey": "..." }`
- **所在类**: `com.giggleacademy.app.api.controller.BookController`

---

## 3. 修改接口测试

### 3.1 书籍推荐-体验课与故事书
- **接口描述**: 推荐体验课与故事书
- **请求方法**: GET
- **请求路径**: `/book/recommend/bookAndCourse`
- **变更点**: 新增 `abTest` 参数
- **鉴权**: PublicApi
- **请求参数（新增/变更）**:
  - `abTest` (query, boolean, 可选，默认 false)
- **影响**: 推荐策略可能根据 A/B 测试参数返回不同结果
- **所在类**: `com.giggleacademy.app.api.controller.BookController`

### 3.2 后台-获取体验课推荐规则
- **接口描述**: 获取体验课程推荐 SpEL 规则
- **请求方法**: GET
- **请求路径**: `/course/recommend/spelRules`
- **变更点**: 新增 `abTest` 参数
- **鉴权**: AdminApi
- **请求参数（新增/变更）**:
  - `abTest` (query, boolean, 可选，默认 false)
- **所在类**: `com.giggleacademy.app.admin.controller.AdminController`

### 3.3 后台-设置体验课推荐规则
- **接口描述**: 设置体验课程推荐 SpEL 规则
- **请求方法**: POST
- **请求路径**: `/course/recommend/spelRules`
- **变更点**: 新增 `abTest` 参数
- **鉴权**: AdminApi
- **请求参数（新增/变更）**:
  - `abTest` (query, boolean, 可选，默认 false)
  - `rules` (body, `CourseRecommendRulesReq`, 必填)
- **所在类**: `com.giggleacademy.app.admin.controller.AdminController`

---

## 4. 删除接口测试
- 本次对比无接口删除

---

## 5. 分支对比分析详情

### 5.1 变更文件（与接口相关）
- `src/main/kotlin/com/giggleacademy/app/api/controller/BookController.kt`
- `src/main/kotlin/com/giggleacademy/app/api/controller/GachaActivityController.kt`
- `src/main/kotlin/com/giggleacademy/app/admin/controller/AdminController.kt`

### 5.2 提交历史（摘要）
- release/1.20.0 相比 develop 包含若干与接口相关的改动（新增与参数调整）

---

## 6. 测试建议

### 6.1 新增接口用例建议
- **GET /activity/gacha/list**: 校验无/有 `language` 参数的返回内容与排序
- **POST /book/{bookId}/indexAudio/{language}**: 文件上传成功、格式校验、权限校验、S3 Key 返回
- **GET /book/{bookId}/indexAudio/{language}**: Public 获取对应 Key，校验不存在/无语言等边界

### 6.2 修改接口回归建议
- **GET /book/recommend/bookAndCourse**: 校验 `abTest=true/false` 结果差异、与旧逻辑兼容
- **GET/POST /course/recommend/spelRules**: 校验 `abTest` 分支规则的读取与更新闭环

### 6.3 一般回归
- 鉴权拦截器路径前缀与权限控制回归
- 书籍推荐、课程推荐相关缓存/参数默认值回归

---

## 7. 测试报告模板（占位）

### 7.1 用例结果
| 测试项 | 用例总数 | 通过 | 失败 | 通过率 |
|---|---:|---:|---:|---:|
| 新增接口 | - | - | - | - |
| 修改接口 | - | - | - | - |
| 回归用例 | - | - | - | - |
| 总计 | - | - | - | - |

### 7.2 缺陷统计
| 严重级别 | 数量 | 状态 |
|---|---:|---|
| P0 | - | - |
| P1 | - | - |
| P2 | - | - |
| P3 | - | - |

---

## 8. 附录
- 参考类：`BookController`、`GachaActivityController`、`AdminController`
- 相关文档：部署文档、数据库设计文档、用户手册

---

**文档版本**: v1.0  
**创建日期**: 2025年10月  
**最后更新**: 2025年10月  
**审核人**: [姓名]

