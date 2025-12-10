from time import strftime

import pytest
from pandas import DataFrame

from test_case.page_api.admin.admin_course_api import AdminCourseApi
from test_case.page_api.user.user_api import UserApi

user = UserApi()
admin_course = AdminCourseApi()
authorization, user_id = user.get_authorization()
admin_auth, user_admin_id = admin_course.get_admin_authorization()

@pytest.fixture(scope='session')
def kid_data_session():
    '''创建测试学生'''
    try:
        # 创建测试学生
        kid_name = 'dibo_test_kid' + strftime("%Y%m%d%H%M%S")
        kid_id = user.createkid(authorization, kid_name)['data']['id']
    except Exception as err:
        print('创建测试学生失败，原因是：', err)
    yield kid_id, kid_name
    # 删除测试学生
    try:
        user.deletekid(authorization, kid_id)
    except Exception as err:
        print('删除测试学生失败，原因是：', err)

@pytest.fixture(scope='session')
def get_course_ids_session():
    """获取课程详情包括版本信息"""
    try:
        # 获取顶层课程目录列表
        topcategory_res = admin_course.getAlltopcategory(admin_auth)
        for category in topcategory_res['data']:
            parentId = category['id']
            # 获取课程子目录列表
            category_res1 = admin_course.getAllsubcategory(admin_auth, parentId)
            for subcategory in category_res1['data']:
                parentId1 = subcategory['id']
                category_res2 = admin_course.getAllsubcategory(admin_auth, parentId1)
                for subcategory2 in category_res2['data']:
                    categoryId = subcategory2['id']
                    # 获取分类下所有课程
                    courselistAll = admin_course.course_listAll(admin_auth, categoryId)['data']
                    if not courselistAll:
                        continue
                    courseIds = DataFrame(courselistAll)['id'].tolist()
                    return courseIds
    except Exception as err:
        print('获取课程详情包括版本信息失败，原因是：', err)
