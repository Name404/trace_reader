#!/usr/bin/env python3
# coding=utf-8
# Written by 帅力
# Date：2019/9/27

import subprocess
from time import sleep


# 抓包，呼叫，停止抓包的操作过程，demo看main函数
class TraceCapture:
    
    def __init__(self, bpf_filter: str = None, location: str = None, log=None):
        '''

        :param bpf_filter: 抓包过滤器
        :param location: 抓包保存路径，带文件名
        '''
        self.bpf_filter = bpf_filter
        self.location = location
        self.log = log
    
    def __enter__(self):
        subprocess.Popen("tshark -i 1 -f '" + str(self.bpf_filter) + "' -w '" + str(self.location) + "'", shell=True)
        self.log.debug('start capturing with: %s, save to %s.' % (self.bpf_filter, self.location))
        sleep(8)
    
    def __exit__(self, type, value, trace):
        subprocess.Popen('killall tshark', shell=True)
        print('ending capture...')
        sleep(5)


def start_capture(bpf_filter=None, location=None):
    '''
    按bpf_filter条件过滤数据包，并存到localtion
    :param bpf_filter: 抓包过滤条件
    :param location:
    :return:
    '''
    subprocess.Popen("tshark -i 1 -f '" + bpf_filter + "' -w '" + location + "'", shell=True)
    pass


def end_capture():
    subprocess.Popen('killall tshark', shell=True)


if __name__ == '__main__':
    # Demo
    with TraceCapture('host 192.168.85.192', '/home/leo/test.pcap') as tc:
        make_call_via_line("2556", 1, 0, 1)
        sleep(5)
        off_hook(2)
        sleep(20)
        on_hook(2)
