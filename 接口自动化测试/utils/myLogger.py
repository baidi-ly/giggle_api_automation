import logging
import os
import traceback
from logging import handlers

level_relations = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'crit': logging.CRITICAL
}  # 日志级别关系映射


class MyLogger:
    def __init__(self, filename, level='info', when='D', back_count=3, fmt=None, **kwargs):
        s = traceback.format_stack()
        case_path = [dt for dt in s if 'test_case\\' in dt]
        set_name = case_path[0] if case_path else s[-1]
        self.fmt = fmt or '%(asctime)s - {} - %(levelname)s: %(message)s'.format(set_name)
        # 日志存放目录
        self.dir_name = kwargs['dir_name'] if 'dir_name' in kwargs and kwargs['dir_name'] else os.path.join(
            os.getcwd().split(r"test_case")[0], 'logs')
        self.dir_name = os.path.abspath(self.dir_name)
        if not os.path.exists(self.dir_name):
            os.makedirs(self.dir_name)
        self.file_path = os.path.join(self.dir_name, filename)
        self.logger = logging.getLogger(self.file_path)
        format_str = logging.Formatter(self.fmt)  # 设置日志格式
        self.logger.setLevel(level_relations.get(level))  # 设置日志级别
        # 往文件里写入
        th = handlers.TimedRotatingFileHandler(filename=self.file_path, when=when, backupCount=back_count,
                                               encoding='utf-8')  # 指定间隔时间自动生成文件的处理器
        th.setFormatter(format_str)  # 设置文件里写入的格式
        self.logger.addHandler(th)  # 把对象加到logger里
        if 'is_stream_handle' in kwargs and kwargs['is_stream_handle']:
            sh = logging.StreamHandler()  # 往屏幕上输出
            sh.setFormatter(format_str)  # 设置屏幕上显示的格式
            self.logger.addHandler(sh)
