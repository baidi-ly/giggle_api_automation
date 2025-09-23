# 接口变更文档 - develop vs release/1.19.0

## 概述
本文档记录了从develop分支到release/1.19.0分支的所有接口变更，包括新增接口和修改的接口。

## 变更统计
- **新增接口**: 12个
- **修改接口**: 1个
- **涉及文件**: 18个

## 新增接口

### 1. 活动管理相关接口 (AdminController)

#### 1.1 创建活动
- **接口路径**: `POST /admin/activity/create`
- **功能描述**: 创建新的活动
- **请求参数**: CreateActivityReq
  - name: String (活动名称，必填，最大255字符)
  - activityCode: String (活动编码，必填，最大50字符)
  - startTime: LocalDateTime (活动开始时间，必填，格式：yyyy-MM-dd HH:mm:ss)
  - endTime: LocalDateTime (活动结束时间，必填，格式：yyyy-MM-dd HH:mm:ss)
  - description: String (活动描述，可选，最大1000字符)
  - status: ActivityStatus (活动状态，必填)
  - rewardConfig: String (奖励配置，可选，最大2000字符)
- **响应**: RestResponse<ActivityResponse>

#### 1.2 更新活动
- **接口路径**: `PUT /admin/activity/{activityId}`
- **功能描述**: 更新指定活动信息
- **路径参数**: activityId (Long) - 活动ID
- **请求参数**: UpdateActivityReq
- **响应**: RestResponse<ActivityResponse>

#### 1.3 更新活动状态
- **接口路径**: `PUT /admin/activity/status`
- **功能描述**: 更新活动状态
- **请求参数**: UpdateActivityStatusReq
- **响应**: RestResponse<String>

#### 1.4 获取活动列表
- **接口路径**: `GET /admin/activity/list`
- **功能描述**: 分页获取活动列表
- **请求参数**: 
  - page: Int (页码，默认0)
  - size: Int (每页大小，默认10)
  - status: ActivityStatus (活动状态，可选)
- **响应**: RestResponse<Page<ActivityResponse>>

#### 1.5 获取活动详情
- **接口路径**: `GET /admin/activity/{activityId}`
- **功能描述**: 根据ID获取活动详情
- **路径参数**: activityId (Long) - 活动ID
- **响应**: RestResponse<ActivityResponse>

#### 1.6 创建活动任务
- **接口路径**: `POST /admin/activity/task`
- **功能描述**: 为活动创建任务
- **请求参数**: CreateActivityTaskReq
- **响应**: RestResponse<ActivityTaskResponse>

#### 1.7 更新活动任务
- **接口路径**: `PUT /admin/activity/task/{id}`
- **功能描述**: 更新活动任务
- **路径参数**: id (Long) - 任务ID
- **请求参数**: UpdateActivityTaskReq
- **响应**: RestResponse<ActivityTaskResponse>

#### 1.8 获取活动任务详情
- **接口路径**: `GET /admin/activity/task/{id}`
- **功能描述**: 获取活动任务详情
- **路径参数**: id (Long) - 任务ID
- **响应**: RestResponse<ActivityTaskResponse>

#### 1.9 获取活动任务列表
- **接口路径**: `GET /admin/activity/task/list`
- **功能描述**: 分页获取活动任务列表
- **请求参数**: 
  - page: Int (页码，默认0)
  - size: Int (每页大小，默认10)
  - activityId: Long (活动ID，可选)
- **响应**: RestResponse<Page<ActivityTaskResponse>>

#### 1.10 获取活动的所有任务
- **接口路径**: `GET /admin/activity/{activityId}/task`
- **功能描述**: 获取指定活动的所有任务
- **路径参数**: activityId (Long) - 活动ID
- **响应**: RestResponse<List<ActivityTaskResponse>>

#### 1.11 删除活动任务
- **接口路径**: `DELETE /admin/activity/task/{id}`
- **功能描述**: 删除活动任务
- **路径参数**: id (Long) - 任务ID
- **响应**: RestResponse<String>

### 2. 图书管理相关接口 (BookController)

#### 2.1 上传故事书语言层包到S3
- **接口路径**: `POST /book/languageLayers/upload`
- **功能描述**: 上传故事书语言层包到S3存储
- **请求参数**: 
  - file: MultipartFile (文件，必填)
  - bookId: Long (图书ID，必填)
  - languageCode: String (语言代码，必填)
- **响应**: RestResponse<Map<String, String>> (包含s3Key)

## 修改的接口

### 1. 图书相关接口修改 (BookController)
- **修改内容**: 在现有BookController中新增了语言层包上传功能
- **影响范围**: 无破坏性变更，仅新增功能

## 新增的数据模型

### 1. ActivityRequest.kt
- CreateActivityReq: 创建活动请求
- UpdateActivityReq: 更新活动请求
- UpdateActivityStatusReq: 更新活动状态请求
- CreateActivityTaskReq: 创建活动任务请求
- UpdateActivityTaskReq: 更新活动任务请求

### 2. ActivityResponse.kt
- ActivityResponse: 活动响应
- ActivityTaskResponse: 活动任务响应

### 3. ActivityEntity.kt
- ActivityEntity: 活动实体
- ActivityTaskDefinitionEntity: 活动任务定义实体

## 新增的服务类

### 1. ActivityService.kt
- 活动管理服务

### 2. ActivityTaskDefinitionService.kt
- 活动任务定义服务

### 3. ActivityRepository.kt
- 活动数据访问层

## 配置变更

### 1. application.yml
- 新增了活动管理相关的配置项

### 2. 数据库迁移
- 新增了base.v1.19.sql迁移文件
- 包含活动表和活动任务表的创建

## 错误码变更

### 1. RestErrorCode.kt
- 新增了活动相关的错误码定义

## 注意事项

1. **向后兼容性**: 所有新增接口都是向后兼容的，不会影响现有功能
2. **权限控制**: 活动管理接口需要管理员权限
3. **数据验证**: 所有新增接口都包含完整的数据验证
4. **错误处理**: 新增了相应的错误码和处理逻辑

## 测试建议

1. **活动管理功能测试**:
   - 测试活动的创建、更新、删除
   - 测试活动状态的变更
   - 测试活动任务的CRUD操作

2. **文件上传功能测试**:
   - 测试语言层包文件上传
   - 测试不同文件格式的处理
   - 测试文件大小限制

3. **权限测试**:
   - 验证管理员权限控制
   - 测试未授权访问的处理

4. **数据验证测试**:
   - 测试必填字段验证
   - 测试数据格式验证
   - 测试数据长度限制

## 部署注意事项

1. 确保数据库迁移文件正确执行
2. 检查S3存储配置是否正确
3. 验证管理员权限配置
4. 测试文件上传功能是否正常

---
*文档生成时间: 2024年12月19日*
*对比分支: develop vs release/1.19.0*
