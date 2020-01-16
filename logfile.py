# coding=utf-8
# 作者:帅力
# 时间:2018年4月27日


import logging
import os
import time

# from DATA.element_locator.locator_reader import log_path

current_time = time.strftime('%Y_%m_%d_%H_%M_%S')


class Log_to_file:
    def __init__(self, model_name, log_path):
        '''
        :param model_name:生成log时，自动带上当前时间，只需传入头部文件名即可
        '''
        
        current_time = time.strftime('%Y_%m_%d_%H_%M_%S')
        list = [model_name, '_', current_time, '.log']
        log_file_name = "".join(list)
        self.logname = os.path.join(log_path, log_file_name)
        
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)
        print(self.logname)
        # 日志输出格式
        self.formatter = logging.Formatter('[%(asctime)s]:%(message)s')
        
        # 日志输出格式
        self.formatter = logging.Formatter('[%(asctime)s]:%(message)s')
    
    def __console(self, level, message):
        # 创建一个FileHandler，用于写到本地
        fh = logging.FileHandler(self.logname, 'a')  # 追加模式
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(self.formatter)
        self.logger.addHandler(fh)
        
        # 创建一个StreamHandler,用于输出到控制台
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(self.formatter)
        self.logger.addHandler(ch)
        
        if level == 'info':
            self.logger.info(message)
        elif level == 'debug':
            self.logger.debug(message)
        elif level == 'warning':
            self.logger.warning(message)
        elif level == 'error':
            self.logger.error(message)
        # 这两行代码是为了避免日志输出重复问题
        self.logger.removeHandler(ch)
        self.logger.removeHandler(fh)
        # 关闭打开的文件
        fh.close()
    
    def debug(self, message):
        print(current_time + ':' + message)
        self.__console('debug', message)
    
    def info(self, message):
        self.__console('info', message)
    
    def warning(self, message):
        self.__console('warning', message)
    
    def error(self, message):
        self.__console('error', message)


if __name__ == "__main__":
    log = Log_to_file('boe777', '/home/leo/')
    log.info("---测试开始----" + '1.0.11.1')
    log.info("输入密码")
    log.warning("----测试结束----")
    log.warning("----测试结束----")
