import sys,os # 即添加包名的搜索路径
sys.path.append(os.path.join(os.path.abspath(__file__).split("page_api")[0],"page_api"))

def public_api():
    return None

__all__ = [
    "hrm"
]