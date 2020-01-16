#!/usr/bin/env python3
# coding=utf-8
# Written by 帅力
# Date：2019/9/27

import traceback

import pyshark

from logfile import Log_to_file


class Trace_Analysist(object):
    '''
    解析包含一个完整呼叫流程的数据包，要求呼叫流程必须完整且唯一，
    内部实现方法对应testlink用例中校验数据包的内容
    '''
    
    def __init__(self, trace_file, display_filter, log):
        self.trace_file = trace_file
        self.trace_pkt = pyshark.FileCapture(trace_file, display_filter=display_filter)
        self.log = log
    
    def reload_tracefile(self, display_filter):
        '''
        在一些情况下，创建实例时使用的过滤条件不能完全满足需要，此时可用本方法重载数据包
        :param display_filter: 过滤显示条件
        :return: FileCapture对象的实例
        '''
        self.log.debug('reload trace with filter: %s' % display_filter)
        return pyshark.FileCapture(self.trace_file, display_filter=display_filter)
    
    def check_status_exist(self, status_code, value='') -> bool:
        '''
        检查数据包中是否存在指定的回应，例如404,486,483等等
        :param status_code: response code
        :param value: 在指定回应中查找特定字段内容，为空时不影响返回结果
        :return: bool
        '''
        self.log.debug('checking status %s exists.' % status_code)
        for i, packet in enumerate(self.trace_pkt):
            try:
                if packet.sip.status_code == status_code:
                    if value in str(packet.sip):
                        self.log.debug('packet exists: %s' % packet.sip)
                        return True
            
            except:
                continue
        self.log.debug('packet NOT exists.')
        return False
    
    def check_bye_exist(self, sender: str, recver: str) -> bool:
        '''
        检查数据包中存在指定的bye信令
        :param sender: 传入bye信令的发送方
        :param recver: 传入bye信令的接受方
        :return: bool
        '''
        dis_filter = ''.join((
            "sip.Method contains \"BYE\" && sip.From contains \"",
            sender,
            "@\" && sip.To contains \"",
            recver,
            "@\""))
        tmp_pkt = self.reload_tracefile(dis_filter)
        
        try:
            self.log.debug(tmp_pkt[0].sip)
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        pass
    
    def check_session_timer_supported(self, caller, callee):
        '''检查invite中supported字段包含timer方法'''
        self.log.debug('checking session timer switch status.')
        if '.' not in (caller + callee):
            dis_filter_invite = ''.join((
                "sip.Method contains \"INVITE\" && sip.From contains \"",
                caller,
                "@\" && sip.To contains \"",
                callee,
                "@\""))
        else:
            dis_filter_invite = ''.join((
                "sip.Method contains \"INVITE\" && sip.From contains \"",
                caller,
                "\" && sip.To contains \"",
                callee,
                "\""))
        try:
            self.log.debug(self.reload_tracefile(dis_filter_invite)[0].sip)
            return 'timer' in str(self.reload_tracefile(dis_filter_invite)[0].sip.supported)
        except:
            self.log.debug(traceback.print_exc())
            self.log.debug('None packet displayed with filter: %s' % dis_filter_invite)
            return 'timer' in str(self.reload_tracefile(dis_filter_invite)[0].sip.supported)
        
        pass
    
    def check_stimer_header(self, refresh_method='invite', session_expir='180', min_se='90'):
        '''
        检查session timer的超时和最小时间字段的值，invite和 200 ok中均可能含有

        :param sip_method: invite 或 200
        :param session_expir: 超时时间
        :param min_se: 最小更新时间
        :return: bool
        '''
        self.log.debug('checking session timer header: expiration and min-se')
        if refresh_method is 'invite':
            dis_filter = ''.join(
                ('sip.Min-SE contains "', min_se, '" && sip.Session-Expires contains "', session_expir,
                 '" && sip.Method contains "INVITE"')
            )
        elif refresh_method is '200':
            dis_filter = ''.join(
                ('sip.Session-Expires contains "', session_expir,
                 '" && sip.Status-Line contains "200 OK"')
            )
        
        else:
            self.log.debug('error parameter sip method parameter:%s' % refresh_method)
            return None
        self.log.debug('display filter: %s' % dis_filter)
        try:
            self.log.debug(self.reload_tracefile(dis_filter)[0].sip)
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        pass
    
    def check_stimer_refresh_msg_interval(self, refresh_method='update', refresher='uac',
                                          update_interval=90):
        '''
        检查更新timer的方法，更新者-主被叫，返回更新间隔结果，若超出update_interval正负1，返回false
        :param refresh_method: 更新会话用的信令方法
        :param refresher: 更新会话发起方
        :param update_interval: 更新时间间隔，min-se取值，默认90
        :return: bool
        '''
        self.log.debug('checking session timer refresh method and refresher.')
        
        dis_filter = ''.join(
            (
                'sip.Session-Expires contains "refresher=',
                refresher,
                '" && sip.Method == "',
                refresh_method.upper(),
                '"')
        )
        interval_list = []
        tmp_pkt = self.reload_tracefile(dis_filter)
        try:
            while True:
                interval_list.append(tmp_pkt.next().frame_info.time_delta_displayed)
        except:
            self.log.debug("detailed interval list %s" % interval_list)
        
        finally:
            if interval_list:
                sum = 0
                for i in interval_list[1:]:
                    sum += float(i)
                average_interval = sum / (len(interval_list) - 1)
                self.log.debug('average interval of update message: %s' % average_interval)
                if update_interval - 1 <= average_interval <= update_interval + 1:
                    return True
                else:
                    return False
            else:
                return False
        
        pass
    
    def check_dtmf_msg(self, sender_ip, recver_ip, dtmf_key, dtmf_type=1):
        '''
        查看数据包中是否存在符合发送方、接受方、dtmf内容和类型的数据包
        :param sender_ip: dtmf消息发送方, ip地址
        :param recv_ip: dtmf消息接收方, ip地址
        :param dtmf_key: 内容，0-9，#，*
        :param dtmf_type: 1-rfc2833, 2-sip-info
        :return: bool
        '''
        self.log.debug('checking dtmf type: %s, key:%s, from %s to %s' % (dtmf_type, dtmf_key, sender_ip, recver_ip))
        if dtmf_type == 1:
            dis_filter = ''.join(('ip.src == ', sender_ip, ' && ',
                                  'ip.dst==', recver_ip, ' &&',
                                  'rtpevent.end_of_event==1&&',
                                  'rtpevent.event_id==', dtmf_key))
            try:
                if self.reload_tracefile(dis_filter)[0].rtpevent:
                    self.log.debug(self.reload_tracefile(dis_filter)[0].rtpevent)
                    return True
                else:
                    self.log.debug("filter:%s, doesn't have correct packets" % dis_filter)
                    return False
            except:
                self.log.debug(traceback.print_exc())
                return False
        
        elif dtmf_type == 2:
            dis_filter = 'sip.Method == "INFO"'
            # pkt.reload_tracefile('sip.Method == "INFO"')[0].sip
            target_str = ''.join(('Signal=', str(dtmf_key)))
            tmp_pkt = self.reload_tracefile(dis_filter)
            try:
                while True:
                    tmp_layer = tmp_pkt.next().sip
                    if target_str in str(tmp_layer):
                        self.log.debug('target dtmf signal:%s exists' % target_str)
                        return True
                    else:
                        continue
            except:
                traceback.print_exc()
                self.log.debug('target dtmf signal:%s not found' % target_str)
                return False
        pass
    
    def get_stimer_refresher(self):
        '''
        获取session timer的更新方，从信令的session expiration字段中查找uas或uac
        :return: uas、uac
        '''
        try:
            tmp_pkt = self.reload_tracefile('sip.Session-Expires contains "refresher"')
            return tmp_pkt[0].sip.session_expires[-3:]
        except:
            return ''
        
        pass
    
    def check_rtp_dtmf_payload(self, payload_value):
        '''
        搜索DynamicRTP的payload, DynamicRTP-Type-119
        :param payload_value 设置的dtmf\rtp载荷值
        :return bool
        '''
        self.log.debug('searching for payload value: %s' % payload_value)
        dis_fileter = ''.join(('sdp.media.format contains "DynamicRTP-Type-', payload_value, '"'))
        try:
            self.log.debug(self.reload_tracefile(dis_fileter)[0])
            self.log.debug('DTMF payload found in SDP')
            return True
        except:
            self.log.debug('DTMF payload NOT found in SDP')
            self.log.debug(traceback.print_exc())
            return False
        
        pass
    
    def check_request_with_value_exist(self, request_method, header='', value='') -> bool:
        '''
        检查数据包中是否存在包含指定头域值的指定的request，例如INVITE，ACK，BYE，
        :param value: 指定头域的值
        :param request_method: 请求方法
        :param 需要在方法中检查的值
        :return: bool
        '''
        tmp_pkt = self.reload_tracefile("sip.Method == \"" + request_method.upper() + "\"")
        for i, packet in enumerate(tmp_pkt):
            try:
                if packet.sip.Method == request_method:
                    if header in str(packet.sip):
                        if value in str(packet.sip):
                            return True
                    else:
                        continue
                else:
                    continue
            except:
                continue
        return False
    
    def check_invite_exist(self, caller: str, callee: str) -> bool:
        '''
        检查符合传入的呼叫方与被叫方的invite请求存在于数据包中
        :param caller: 发起invite的主叫方
        :param callee: 接受invite的被叫方
        :return: bool
        '''
        dis_filter = ''.join((
            "sip.Method == \"INVITE\" && sip.From contains \"",
            caller,
            "@\" && sip.To contains \"",
            callee,
            "@\""))
        tmp_pkt = self.reload_tracefile(dis_filter)
        
        self.log.debug('display filter: ' + dis_filter)
        
        try:
            self.log.debug('packet: %s' % tmp_pkt[0].sip)
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        
        pass
    
    def check_invite_sendonly(self) -> bool:
        return self.check_request_with_value_exist('INVITE', 'sendonly')
    
    def check_invite_sendrecv(self) -> bool:
        return self.check_request_with_value_exist('INVITE', 'sendrecv')
    
    def check_syslog_match_ring_tone(self, ring_tone_index) -> bool:
        '''
        检查指定序号的铃声是否在syslog中存在
        :param ring_tone_index: 过滤匹配铃声时，铃声在syslog中的序号
        :return: bool
        '''
        self.log.debug('checking syslog of matched ringtone value.')
        dis_filter = 'syslog.msg contains "(' + str(ring_tone_index) + ') based on"'
        self.log.debug('display filter: ' + dis_filter)
        
        try:
            self.log.debug('packet: %s' % self.reload_tracefile(dis_filter)[0])
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        
        pass
    
    def check_syslog_invalid_number(self):
        '''case66,testcase_1181，呼叫转移到不符合拨号规则的号码，不会发出sip信令，只能检查syslog'''
        
        self.log.debug('checking syslog of mis-match dial plan call failed error.')
        dis_filter = 'syslog.msg contains \"dialPlanEngine:" && syslog.msg contains "error"'
        self.log.debug('display filter: ' + dis_filter)
        
        try:
            self.log.debug('packet: %s' % self.reload_tracefile(dis_filter)[0])
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        
        pass
    
    def check_call_established(self, caller: str, callee: str, srv_mode: str = 'openser') -> bool:
        '''
        检查正常呼叫建立过程，检查主叫方，被叫方正确
        检查点：
        1、invite中的from_user,to_user，
        2、200OK中的from_user, to_user,
        3、invite，200中的call-id一致

        :param caller: 主叫号码
        :param callee: 被叫号码
        :param srv_mode: 区分,openser 和 ucm,二者呼叫检查方式不同
        :return: bool
        '''
        self.log.debug('checking call established between %s and %s with mode %s.' % (caller, callee, srv_mode))
        if '.' not in (caller + callee):
            dis_filter_invite = ''.join((
                "sip.Method contains \"INVITE\" && sip.From contains \"",
                caller,
                "@\" && sip.To contains \"",
                callee,
                "@\""))
            
            dis_filter_200OK = ''.join((
                "sip.Status-Line == \"SIP/2.0 200 OK\" && sip.From contains \"",
                caller,
                "@\" && sip.To contains \"",
                callee,
                "@\""))
        
        else:
            dis_filter_invite = ''.join((
                "sip.Method contains \"INVITE\" && sip.From contains \"",
                caller,
                "\" && sip.To contains \"",
                callee,
                "\""))
            
            dis_filter_200OK = ''.join((
                "sip.Status-Line == \"SIP/2.0 200 OK\" && sip.From contains \"",
                caller,
                "\" && sip.To contains \"",
                callee,
                "\""))
        
        try:
            call_id_1 = self.reload_tracefile(dis_filter_invite)[0].sip.call_id
        except:
            self.log.debug(traceback.print_exc())
            
            return False
        
        try:
            call_id_2 = self.reload_tracefile(dis_filter_200OK)[0].sip.call_id
        except:
            self.log.debug(traceback.print_exc())
            
            return False
        
        if srv_mode == 'openser':
            
            if call_id_2 == call_id_1:
                return True
            else:
                return False
        
        elif srv_mode == 'ucm':
            if call_id_1 and call_id_2:
                return True
            else:
                return False
        else:
            return False
    
    def check_dns_process(self, domain, ip_addr) -> bool:
        '''
        检查dns回复中是否存在参数域名和地址的绑定
        :param domain: 域名
        :param ip_addr: ip地址
        :return: bool
        '''
        self.log.debug('checking DNS request of %s ' % (domain))
        
        dis_filter = ''.join(('dns.qry.name contains "', domain, '"',
                              '&&', 'dns.a == ', ip_addr,))
        
        self.log.debug('display filter: ' + dis_filter)
        
        try:
            self.log.debug('packet: %s' % self.reload_tracefile(dis_filter)[0])
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        pass
    
    def check_dns_request_type(self, domain, dns_type='A', tcp_option=0) -> bool:
        '''
        查看指向域名的dns请求是否为参数对应的类型
        :param domain: 域名
        :param dns_type: dns请求类型，取值--A，SRV，NAPTR
        :return: bool
        '''
        dns_type_num = ''
        domain_srv = ''
        dis_filter = ''
        
        if tcp_option == 1:
            domain_srv = ''.join(('_sip._tcp.', domain))
        elif tcp_option == 0:
            domain_srv = ''.join(('_sip._udp.', domain))
        
        if dns_type == "A":
            dns_type_num = '1'
            dis_filter = ''.join(('dns.qry.name contains "', domain, '"',
                                  '&&', 'dns.qry.type == ', dns_type_num))
        elif dns_type == "SRV":
            dns_type_num = '33'
            dis_filter = ''.join(('dns.qry.name contains "', domain_srv, '"',
                                  '&&', 'dns.qry.type == ', dns_type_num))
        elif dns_type == 'NAPTR':
            dns_type_num = '35'
            dis_filter = ''.join(('dns.qry.name contains "', domain, '"',
                                  '&&', 'dns.qry.type == ', dns_type_num))
        else:
            return False
        
        self.log.debug('display filter: ' + dis_filter)
        try:
            self.log.debug('packet: %s' % self.reload_tracefile(dis_filter)[0])
        except:
            self.log.debug(traceback.print_exc())
            return False
        else:
            return True
    
    def check_re_invite_ack_with_sdp(self, caller, callee):
        '''检查re-invite过程中，存在着不带sdp的INVITE，和ACK携带sdp协商通话的过程'''
        self.log.debug('checking ACK with SDP message from %s to %s.' % (caller, callee))
        dis_filter = ''.join((
            "sip.Method contains\"ACK\" && sdp && sip.From contains \"",
            caller,
            "@\" && sip.To contains \"",
            callee,
            "@\""))
        self.log.debug('display filter: ' + dis_filter)
        try:
            self.log.debug('packet: %s' % self.reload_tracefile(dis_filter)[0].sip)
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        
        pass
    
    def check_anonymous_invite(self, callee: str):
        '''检查发出的invite是否为匿名呼叫'''
        self.log.debug('checking anonymous invite exists.')
        dis_filter = 'sip.Method contains "INVITE" && sip.From contains "Anonymous"' + '&& sip.To contains "' + str(
            callee) + '@"'
        try:
            self.log.debug('packet: %s' % self.reload_tracefile(dis_filter)[0])
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
    
    def check_notify_after_refer(self):
        '''attend transfer的数据包中，用于检查匹配refer的notify是否存在'''
        dis_filter = "sip.Method contains \"NOTIFY\" && sip.Event == \"refer\""
        self.log.debug('checking NOTIFY with refer exists.')
        try:
            self.log.debug('packet: %s' % self.reload_tracefile(dis_filter)[0])
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
    
    def get_pkt_by_method(self, request_method: str):
        pkt = []
        for packet in self.trace_pkt:
            try:
                if packet.sip.Method == request_method:
                    pkt.append(packet.sip)
                else:
                    continue
            except:
                self.log.debug(traceback.print_exc())
                
                continue
        
        try:
            self.log.debug('packet: %s' % pkt[0].sip)
            return True
        except:
            self.log.debug(traceback.print_exc())
            
            return False
        pass
    
    def check_hold_call(self, caller: str, callee: str) -> bool:
        '''
        1、检查呼叫保持信令关键字sendonly
        2、检查呼叫保持方与被保持方

        :param caller:保持发起方
        :param callee:被保持方
        :return: bool
        '''
        self.log.debug('checking hold process from %s to %s.' % (caller, callee))
        dis_filter = ''.join((
            "sip.Method contains\"INVITE\" && sdp.media_attr == \"sendonly\" && sip.From contains \"",
            caller,
            "@\" && sip.To contains \"",
            callee,
            "@\""))
        self.log.debug('display filter: ' + dis_filter)
        
        try:
            self.log.debug('packet: %s' % self.reload_tracefile(dis_filter)[0].sip)
            return True
        except:
            self.log.debug(traceback.print_exc())
            
            return False
        
        pass
    
    def check_rtp_direction(self, sender_ip: str, recv_ip: str) -> bool:
        '''
        检查从sender发向recver的rtp包存在
        :param sender_ip: 发送方ip
        :param recv_ip:   接受方ip
        :return: bool
        '''
        self.log.debug('checking rtp exists from %s from %s.' % (sender_ip, recv_ip))
        
        dis_filter = ''.join(('rtp&&ip.src==', sender_ip, '&&ip.dst==', recv_ip))
        self.log.debug('display filter: ' + dis_filter)
        
        try:
            self.log.debug('packet: %s' % self.reload_tracefile(dis_filter)[0])
            return True
        except:
            self.log.debug(traceback.print_exc())
            
            return False
    
    def check_recover_call(self, caller: str, callee: str) -> bool:
        '''
        1、检查呼叫保持信令关键字sendrecv
        2、检查呼叫保持方与被保持方

        :param caller:保持发起方
        :param callee:被保持方
        :return: bool
        '''
        self.log.debug('checking recover call between caller: %s and callee: %s.' % (caller, callee))
        dis_filter = ''.join((
            "sdp.media_attr == \"sendrecv\" && sip.From contains \"",
            caller,
            "@\" && sip.To contains \"",
            callee,
            "@\""))
        self.log.debug('display filter: ' + dis_filter)
        try:
            self.log.debug('packet: %s' % self.reload_tracefile(dis_filter)[0].sip)
            return True
        except:
            self.log.debug(traceback.print_exc())
            
            return False
        pass
    
    def check_register(self, register_str):
        '''检查注册消息中是否包含传入的register_str'''
        self.log.debug('checking register server uri:%s' % register_str)
        dis_filter = ''.join(('sip.r-uri contains "', register_str, '"'))
        try:
            self.log.debug('packet: %s' % self.reload_tracefile(dis_filter)[0].sip)
            return True
        except:
            self.log.debug(traceback.print_exc())
            
            return False
        pass
    
    def check_proxy(self, proxy_uri: str, sip_register_uri: str) -> bool:
        '''
        检查通过proxy发出的注册信息是否存在于数据包中，特点是数据包ip层目的地址和注册消息中的uri不一致
        :param proxy_uri: proxy代理服务器地址
        :param sip_uri: sip服务器地址
        :return: bool
        '''
        self.log.debug('checking register process via proxy_%s with register info:%s' % (proxy_uri, sip_register_uri))
        
        try:
            dis_filter = ''.join(('sip.r-uri contains "', sip_register_uri,
                                  '" && ip.dst == ', proxy_uri.split(":")[0],
                                  '&&udp.dstport == ', proxy_uri.split(":")[1],
                                  ' && sip && not icmp'))
        except:
            dis_filter = ''.join(('sip.r-uri contains "', sip_register_uri,
                                  '" && ip.dst == ', proxy_uri.split(":")[0],
                                  ' && sip && not icmp'))
        try:
            self.log.debug('packet: %s' % self.reload_tracefile(dis_filter)[0].sip)
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        pass
    
    def check_refer_correct(self, refered_by: str, refer_to: str) -> bool:
        '''
        检查refer信令中，转移方和被转移方符合实际操作
        :param refered_by: 转移的发起方
        :param refer_to: 转移的被叫方
        :return: bool，符合实际转移方和被转移方的，返回true
        '''
        
        self.log.debug('checking REFER method of refer-by: %s and refer-to: %s.' % (refered_by, refer_to))
        
        dis_filter_refer = ''.join((
            "sip.Method contains \"REFER\" && sip.Refered-by contains \"",
            refered_by,
            "@\" && sip.Refer-To contains \"",
            refer_to,
            "@\""))
        try:
            self.log.debug('refer packet: %s' % self.reload_tracefile(dis_filter_refer)[0].sip)
            return True
        except:
            self.log.debug(traceback.print_exc())
            
            return False
    
    def check_t_conf(self, conf_holder: str, callee_1: str, callee_2: str, conf_holder_2: str = None,
                     srv_mode='openser') -> bool:
        '''
        检查三方会议信令过程
        1、检查con_holder与callee_1的通话建立
        2、检查con_holder保持与callee_1的通话
        3、检查con_holder与callee_2的通话建立
        4、检查con_holder恢复与callee_1的通话

        :param conf_holder: 三方会议发起方
        :param conf_holder_2: 三方会议发起方用于呼叫第二方的账号，有三方通话跨线路建立的测试用例
        :param callee_1: 第一个被叫
        :param callee_2: 第二个被叫
        :param srv_mode: sip服务器类型，openser、UCM
        :return: bool
        '''
        
        if conf_holder_2 is None:
            self.log.debug(
                'checking T-CONF between holder: %s and party: %s and %s. ' % (conf_holder, callee_1, callee_2))
            result_tuple = (self.check_call_established(conf_holder, callee_1, srv_mode),
                            self.check_call_established(conf_holder, callee_2, srv_mode),
                            self.check_recover_call(conf_holder, callee_1))
        else:
            self.log.debug(
                'checking T-CONF between holder_1: %s, holder_2: %s and party: %s and %s. '
                % (conf_holder, conf_holder_2, callee_1, callee_2))
            result_tuple = (self.check_call_established(conf_holder, callee_1, srv_mode),
                            self.check_call_established(conf_holder_2, callee_2, srv_mode),
                            self.check_recover_call(conf_holder, callee_1))
        
        self.log.debug('''
            T-conf process:
                1、call from %s to %s:%s
                2、call from %s to %s:%s
                3、t-conf establish: %s
                    ''' % (conf_holder, callee_1, result_tuple[0],
                           conf_holder, callee_2, result_tuple[1],
                           result_tuple[2]))
        if False in result_tuple:
            return False
        else:
            return True
        
        pass
    
    def check_cancel(self, send_num: str, recv_num: str) -> bool:
        '''
        过滤检查cencel请求的存在，和cancel发送方、接收方
        :param send_num:
        :param recv_num:
        :return:bool
        '''
        self.log.debug('checking cancel from %s to %s.' % (send_num, recv_num))
        
        dis_filter = ''.join((
            "sip.Method contains \"CANCEL\" && sip.From contains \"",
            send_num,
            "@\" && sip.To contains \"",
            recv_num,
            "@\""))
        
        try:
            self.log.debug(self.reload_tracefile(display_filter=dis_filter)[0])
            self.log.debug(self.check_status_exist('487'))
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
    
    pass
    
    def check_tls(self) -> bool:
        '''
        检查数据包中是否有tls加密数据，用于测试sip传输协议为tls
        :return:
        '''
        self.log.debug('checking sip via tls.')
        
        try:
            self.log.debug(self.reload_tracefile(display_filter='ssl')[0])
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        pass
    
    def get_parallel_ringing_duration(self):
        '''
        获取同振时，呼叫振铃的超时时间
        :return: duration, float
        '''
        
        dis_filter = 'syslog.msg contains "processEvent: SIG_PARALLEL_RING"  ' \
                     '|| syslog.msg contains "processEvent: STOP_PARALLEL"'
        
        tmp_pkt = self.reload_tracefile(dis_filter)
        parallel_ringing_duration = abs(float(tmp_pkt[0]) - float(tmp_pkt[1]))
        self.log.debug('parallel_ringing_duration in trace: %s' % parallel_ringing_duration)
        return parallel_ringing_duration
        
        pass
    
    def get_hs_ringing_timeout_duration(self, time_out: int):
        '''
        检查DP手柄循环顺序振铃，线性顺序振铃时，手柄振铃间隔控制
        过滤syslog中ring_timeout事件，检查事件间隔时间
        :param time_out: DP中设置的手柄振铃超时时间。
        :return: 过滤syslog后，计算出每条syslog之间的间隔，形成列表，返回该列表
        '''
        syslog_timestamp_list = []
        ringing_duration_list = []
        try:
            for i in self.reload_tracefile('syslog.msg contains "time out = ' + str(time_out) + '"'):
                syslog_timestamp_list.append(i.sniff_timestamp)
            self.log.debug('ringing syslog timestamp: %s' % syslog_timestamp_list)
            
            for i in range(len(syslog_timestamp_list) - 1):
                ringing_duration_list.append(abs(float(syslog_timestamp_list[i]) - float(syslog_timestamp_list[i + 1])))
            self.log.debug('ringing timeout in syslog: %s' % ringing_duration_list)
        except:
            self.log.debug(traceback.print_exc())
        finally:
            self.log.debug('ringing duration: %s' % ringing_duration_list)
            return ringing_duration_list
        
        pass
    
    # def get_ringing_duration(self, hs_index):
    #     '''
    #     获取指定手柄待机到振铃，再回到待机的时间间隔，即振铃时长
    #     :param hs_index: 1-5
    #     :return: float number or 0
    #     '''
    #     try:
    #         tmp = self.reload_tracefile(
    #             'syslog.msg contains "[' + str(hs_index) + '0:0] CALL_RINGING -> CALL_IDLE" ||'
    #                                                        'syslog.msg contains "[' + str(
    #                 hs_index) + '0:0] CALL_IDLE -> CALL_RINGING"')
    #         self.log.debug('frame delta: %s' % str(float(tmp[1].sniff_timestamp) - float(tmp[0].sniff_timestamp)))
    #         return float(tmp[1].sniff_timestamp) - float(tmp[0].sniff_timestamp)
    #     except:
    #         self.log.debug(traceback.print_exc())
    #         return 0
    #     pass
    
    def check_sip_tcp(self) -> bool:
        '''
        检查数据包中sip信令是否用tcp协议传输
        :return:
        '''
        self.log.debug('checking sip via tcp.')
        try:
            self.log.debug(self.reload_tracefile(display_filter='tcp&&sip')[0])
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        pass
    
    def check_proxy_header(self, proxy_url):
        '''
        检查sip信令中是否包含proxy header字段
        :param proxy_url:
        :return: bool
        '''
        self.log.debug('checking proxy header in sip msg.')
        try:
            self.log.debug(self.reload_tracefile(display_filter='sip.Proxy-Require contains "' + proxy_url + '"')[0])
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        pass
    
    def check_alert_info_auto_answer_invite(self, alert_info_str: str = "info=alert-autoanswer;delay=0"):
        '''
        1、检查指定的alert_info_str在invite中存在
        2、返回该invite建立的呼叫是否成功

        :param alert_info_str:
        :return:bool
        '''
        
        self.log.debug('checking alert info paging call auto answer.')
        display_filter = ''.join(('sip.Alert-Info == "', alert_info_str, '"'))
        try:
            self.log.debug(self.reload_tracefile(display_filter=display_filter)[0])
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
    
    def check_stun_request_exists(self, stun_addr):
        '''
        查看是否存在dut向stun发起request的数据包

        :param stun_addr: stun服务器ip地址，不带端口
        :return: bool
        '''
        
        self.log.debug('checking alert info paging call auto answer.')
        display_filter = ''.join(('classicstun && not icmp && ip.src==', stun_addr))
        try:
            self.log.debug(self.reload_tracefile(display_filter=display_filter)[0])
            return True
        
        except:
            self.log.debug(traceback.print_exc())
            return False
        pass
    
    def get_mapped_ip_via_stun(self, stun_addr):
        '''获取stun服务器返回的mapped外网地址'''
        self.log.debug('checking alert info paging call auto answer.')
        display_filter = ''.join(('classicstun && not icmp && ip.src==', stun_addr))
        try:
            return self.reload_tracefile(display_filter=display_filter)[0].classicstun.att_ipv4
        except:
            self.log.debug(traceback.print_exc())
            return None
        pass
    
    def check_nat_ip_in_sdp(self, mapped_ip_in_sdp):
        '''
        启用NAT的stun和static IP后，在invite中的sdp owenr字段应能检查到转换过来的地址
        :param mapped_ip_in_sdp:
        :return:
        '''
        dis_filter = ''.join(('sdp.owner contains "', mapped_ip_in_sdp, '"'))
        try:
            self.log.debug(self.reload_tracefile(display_filter=dis_filter)[0])
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        pass
    
    def check_unsolicited_refer_radio_option(self, radio_index, dut_caller_num) -> bool:
        '''
        检查对应的unsolicited refer选项的处理机制
        :param radio_index: refer选项的索引，0-disable，1-enable，2-enable and auth
        :return:bool
        '''
        if radio_index == 0:
            return self.check_status_exist(status_code='488')
        
        elif radio_index == 1:
            try:
                result_1 = self.check_status_exist(status_code='202')
                self.log.debug('202 status: %s' % result_1)
                tmp = self.reload_tracefile('sip.Method contains"REFER"')[0].sip.refer_to
                result_2 = self.check_call_established(dut_caller_num, tmp)
                self.log.debug('call status: %s' % result_2)
                return result_1 and result_2
            except:
                self.log.debug(traceback.print_exc())
                return False
        
        elif radio_index == 2:
            try:
                result_1 = self.check_status_exist(status_code='401')
                result_2 = self.check_status_exist(status_code='202')
                self.log.debug('401 status: %s. 202 status: %s' % (result_1, result_2))
                tmp = self.reload_tracefile('sip.Method contains"REFER"')[0].sip.refer_to
                self.log.debug('refer ot number: %s' % tmp)
                return result_1 and result_2 and self.check_call_established(dut_caller_num, tmp)
            except:
                self.log.debug(traceback.print_exc())
                return False
        
        pass
    
    def check_opus_stero(self, stero_swtich=0):
        '''
        返回opus编码描述字符串中关于立体声的情况
        开启-rtpmap:125 opus/48000/2
        关闭-rtpmap:125 opus/48000
        :return: True-存在立体声描述，Fals-不存在立体声描述
        '''
        invite_sdp = str(self.reload_tracefile('sdp')[0].sip)
        tmp_list = []
        for i in invite_sdp.splitlines():
            if 'Media Attribute (a)' in i:
                tmp_list.append(i.strip('\t'))
        
        try:
            if stero_swtich == 0:
                target_string = 'Media Attribute (a): rtpmap:125 opus/48000/2'
                for i in tmp_list:
                    if i == target_string:
                        self.log.debug('target string found in sdp:%s' % i)
                        return True
                    else:
                        continue
                self.log.debug('target string of stero opus codec NOT found in sdp')
                return False
            
            elif stero_swtich == 1:
                target_string = 'Media Attribute (a): rtpmap:125 opus/48000'
                for i in tmp_list:
                    if i == target_string:
                        self.log.debug('target string found in sdp:%s' % i)
                        return True
                    else:
                        continue
                self.log.debug('target string of stero opus codec NOT found in sdp')
                return False
        except:
            self.log.debug(traceback.print_exc())
            return False
            pass
        
        pass
    
    # def check_prefer_primary_sip_server_no(self, sec_sip_uri, filter='sip && not icmp && sip.Method contains"REGISTER"'):
    #     '''检查数据包中最后一个注册消息，指向次要sip服务器，因不优先主服务器时，超时后永远向次服务器注册
    #         :param sec_sip_uri 注册消息的request line
    #         :param filter：过滤trace使用的过滤条件
    #         :return bool
    #     '''
    #     #   在测试步骤中需设置超时时间，且在抓包过程中等待大于一半的租约时间，然后配合本检查方法校验用例通过性
    #     #   检查请求注册主服务器的次数，考察整除11的商，不大于1时，代表注册周期内只向主服务器发起过一次请求
    #
    #     last_pkt = self.get_last_pkt(dis_filter=filter)
    #     self.log.debug('checking the last register msg, register uri: %s' % sec_sip_uri)
    #     try:
    #         self.log.debug('last packet of register:%s' % last_pkt.sip.request_line)
    #         if sec_sip_uri in last_pkt.sip.request_line:
    #             self.log.debug('check pass')
    #             return True
    #         self.log.debug('check fail')
    #         return False
    #     except:
    #         self.log.debug('check pass')
    #         return False
    #
    # def check_prefer_primary_sip_server_yes(self, primary_uri, sec_sip_uri,
    #                                         filter='sip && not icmp && sip.Method contains"REGISTER"',
    #                                         register_retry=11) -> bool:
    #     '''
    #     检查超期时优先向主服务器发注册请求，失败后再向备份服务器发注册请求
    #     :param primary_uri: 主uri
    #     :param sec_sip_uri: 备份uri
    #     :param filter: 过滤条件
    #     :param register_retry: 一轮注册消息总共发送的请求次数，DP为11次
    #     :return: bool
    #     '''
    #     #   在测试步骤中需设置超时时间，且在抓包过程中等待大于一半的租约时间，然后配合本检查方法校验用例通过性
    #     #   检查请求注册主服务器的次数，考察整除11的商，大于1时，代表注册周期后重新向主服务器发起过请求
    #
    #     pass
    
    def get_last_pkt(self, dis_filter):
        last_pkt_index = self.get_trace_pkt_count(dis_filter) - 1
        return self.reload_tracefile(dis_filter)[last_pkt_index]
    
    def get_trace_pkt_count(self, filter):
        tmp_trace = self.reload_tracefile(filter)
        i = 0
        try:
            while tmp_trace.next():
                i += 1
        except:
            return i
            pass
    
    def get_voice_codec_order_in_invite(self):
        '''从数据包的invite中获取codec顺序'''
        invite_sdp = str(self.reload_tracefile('sip.Method=="INVITE"')[0].sip)
        tmp_list = []
        codec_order = []
        for i in invite_sdp.splitlines():
            if 'Media Attribute (a)' in i:
                tmp_list.append(i.strip('\t'))
        
        for i in tmp_list:
            for j in ['PCMA', 'PCMU', 'G722', 'G723', 'G729', 'G726', 'iLBC', 'opus']:
                if j in i:
                    codec_order.append(j)
        self.log.debug('codec order in invite sdp: %s' % codec_order)
        return codec_order
        pass
    
    def get_register_round(self, register_uri, register_msg_qty=11, filter='sip.Method contains"REGISTER"'):
        '''
           在测试步骤中需设置超时时间，且在抓包过程中等待大于一半的租约时间，然后配合本检查方法校验用例通过性
           检查请求注册主服务器的次数，考察整除11的商，大于1时，代表注册周期后重新向主服务器发起过请求
        :param register_uri:
        :param filter:
        :return: 数据包中指向register_uri的注册轮数，DP产品一轮注册中会发11个包

        '''
        self.log.debug('calculating register turns...')
        dis_filter = ''.join(('sip.r-uri contains "', register_uri, '" &&', filter))
        tmp_trace = self.reload_tracefile(dis_filter)
        
        pkt_qty = 0
        try:
            while tmp_trace.next():
                pkt_qty += 1
        except:
            self.log.debug('register messge to <<%s>> quantity: %s' % (register_uri, pkt_qty))
            self.log.debug('every register turn, dut will send <<%s>> register requests' % register_msg_qty)
            self.log.debug('register turns: %s' % (pkt_qty // register_msg_qty))
            return pkt_qty // register_msg_qty
            pass
    
    def get_keep_alive_interval(self, dst_ip):
        '''
        获取到指定url心跳包的时间间隔
        :param dst_url:
        :return:
        '''
        dis_filter = ''.join(('classicstun && ip.dst==', dst_ip))
        interval_list = []
        tmp_pkt = self.reload_tracefile(dis_filter)
        try:
            for i in tmp_pkt:
                tmp_interval = round(float(i.frame_info.time_delta_displayed), 2)
                if 5 <= tmp_interval <= 15:
                    interval_list.append(tmp_interval)
            
            self.log.debug('intervals of first 100 pkts with out 0.00 sec: %s' % interval_list)
        except:
            self.log.debug(traceback.print_exc())
        finally:
            max_value = max(interval_list)
            return max_value
    
    def get_keep_alive_pkt_port(self, dst_ip):
        '''
        获取到指定url心跳包消息的目的端口

        :param dst_url:到指定ip地址的数据包的目的端口
        :return: tuple:(src_port,dst_port)
        '''
        dis_filter = ''.join(('classicstun && ip.dst==', dst_ip))
        return self.reload_tracefile(dis_filter)[0].udp.dstport
    
    def get_ptime_of_invite(self):
        '''获取invite中的ptime值'''
        # ptime值取决于首选语音编码
        try:
            return self.reload_tracefile('sip.Method=="INVITE"')[0].sip.sdp_media_attribute_value
        except:
            return 0
    
    def get_dscp_value(self, filter='sip'):
        '''获取sip信令中，IP层DSCP字段的值'''
        try:
            return self.reload_tracefile(filter)[0].ip.dsfield_dscp
        except:
            return None
        pass
    
    def int_to_str(list: list) -> list:
        '''
        change element of list from int to str.
        :param list: list containing int element.
        :return: list containing str element.
        '''
        tmp = []
        for i in list:
            tmp.append(str(i))
        return tmp
    
    def get_g723_bitrate(self, sender_ip):
        '''获取g723语音编码rtp的传输速率读数'''
        dis_filter = ''.join(('rtp&&ip.src==', sender_ip))
        try:
            return self.reload_tracefile(dis_filter)[0].g723
        except:
            self.log.debug(traceback.print_exc())
            return -1
    
    def get_g726_packing_mode(self, sender_ip):
        '''获取g726编码的打包模式'''
        dis_filter = ''.join(('rtp&&ip.src==', sender_ip))
        try:
            return self.reload_tracefile(dis_filter)[0].rtp
        except:
            self.log.debug(traceback.print_exc())
            return -1
    
    def get_ilbc_payload(self, sender_ip):
        '''获取ilbc编码payload'''
        dis_filter = ''.join(('rtp&&ip.src==', sender_ip))
        try:
            return self.reload_tracefile(dis_filter)[0].rtp
        except:
            self.log.debug(traceback.print_exc())
            return -1
    
    def get_matched_codec_list(self):
        '''获取dut做被叫时，协商成功的语音编码列表'''
        dis_filter = 'sip.Status-Line == "SIP/2.0 200 OK" && sdp'
        try:
            invite_sdp = str(self.reload_tracefile(dis_filter)[0].sip)
            tmp_list = []
            matched_codec_list = []
            for i in invite_sdp.splitlines():
                if 'Media Attribute (a)' in i:
                    tmp_list.append(i.strip('\t'))
            
            for i in tmp_list:
                for j in ['PCMA', 'PCMU', 'G722', 'G723', 'G729', 'G726', 'iLBC', 'opus']:
                    if j in i:
                        matched_codec_list.append(j)
            self.log.debug('codec order in invite sdp: %s' % matched_codec_list)
            return matched_codec_list
        except:
            self.log.debug(traceback.print_exc())
            return ''
        pass
    
    def check_rtp_type(self, type='srtp'):
        '''
        检查参数指定类型的rtp消息是否存在于数据包中
        Args:
            type: rtp\srtp

        Returns:
            bool
        '''
        if type == 'srtp':
            target_header = 'SRTP Encrypted Payload'
        elif type == 'rtp':
            target_header = 'Payload:'
        else:
            return False
        try:
            self.log.debug('%s header found in trace' % ('rtp ' + target_header))
            return target_header in str(self.reload_tracefile('rtp')[0])
        except:
            self.log.debug(traceback.print_exc())
            return False
        pass
    
    def get_rtcp_port(self, dut_ip):
        '''
        获取rtcp消息使用的udp端口
        Args:
            dut_ip: rtcp消息发送方

        Returns:
            端口号或none
        '''
        try:
            rtcp_pkt = self.reload_tracefile('rtcp && ip.src==' + dut_ip)[0]
            self.log.debug('rtcp port:%s' % rtcp_pkt.udp.srcport)
            return rtcp_pkt.udp.srcport
        except:
            self.log.debug(traceback.print_exc())
            return None
    
    def check_rtcp_interval(self, rtcp_sender_ip, update_interval=5):
        '''
        获取rtcp包的发送间隔
        Args:
            rtcp_sender_ip: rtcp发送方
            update_interval: 默认更新间隔时间，5s

        Returns:
            当实际间隔为update_interval误差0.5s之内时，返回True，否则False
        '''
        tmp_pkt = self.reload_tracefile('rtcp&&ip.src==' + rtcp_sender_ip)
        interval_list = []
        try:
            while True:
                interval_list.append(tmp_pkt.next().frame_info.time_delta_displayed)
        except:
            self.log.debug("detailed interval list %s" % interval_list)
        
        finally:
            try:
                sum = 0
                for i in interval_list[1:]:
                    sum += float(i)
                average_interval = sum / (len(interval_list) - 1)
                self.log.debug('average interval of update message: %s' % average_interval)
                if update_interval - 0.5 <= average_interval <= update_interval + 0.5:
                    return True
                else:
                    return False
            except:
                self.log.debug(traceback.print_exc())
                return False
        pass
    
    def get_rtcp_pkt_count_tuple(self, sender_ip):
        '''
        校验rtcp包中记录的rtp数量与实际主叫设备发送的rtp包数量是否一致
        采用rtp的seq字段检查rtp包数量，检查每个rtcp前一个rtp的seq
        Args:
            sender_ip: rtcp和rtp的发送方

        Returns:
            查找每一个rtcp包记录的rtp数量，符合要求记录为True，否则为Fals，返回bool类型列表
        '''
        try:
            init_seq = int(self.reload_tracefile('rtp')[0].rtp.seq)
            print('first rtp seq:%s' % init_seq)
        except:
            self.log.debug(traceback.print_exc())
            self.log.debug('no rtp packets in trace file.')
            return (False,)
        
        last_rtp_seq = 0
        result_list = []
        tmp_pkt = self.reload_tracefile('(rtp||rtcp)&&ip.src==' + sender_ip)
        try:
            while True:
                target_pkt = tmp_pkt.next()
                try:
                    last_rtp_seq = int(target_pkt.rtp.seq)
                except:
                    self.log.debug('seq of last rtp before rtcp: %s' % last_rtp_seq)
                    pkt_count = int(target_pkt.rtcp.sender_packetcount)
                    result_list.append((init_seq, last_rtp_seq, pkt_count))
        except:
            traceback.print_exc()
            self.log.debug('packets count and seq tuple:%s' % result_list)
        finally:
            rtcp_count_result = []
            for (first_seq, last_seq, rtp_count) in result_list:
                if rtp_count == (last_seq - first_seq + 1):
                    rtcp_count_result.append(True)
                else:
                    self.log.debug('%s does not match the cauculatation.'
                                   % str((first_seq, last_seq, rtp_count)))
                    rtcp_count_result.append(False)
            return rtcp_count_result
    
    def get_rtp_codec(self) -> str:
        '''
        获取rtp流的语音编码
        0       PCMU
        2	    G726-32
        4       G723
        8       PCMA
        9       G722
        18      G729
        119	    ilbc
        125	    opus
        Returns: 返回rtp流的语音编码

        '''
        codec_dict = {
            '0': 'PCMU',
            '2': 'G726',
            '4': 'G723',
            '8': 'PCMA',
            '9': 'G722',
            '18': 'G729',
            '119': 'iLBC',
            '125': 'OPUS'
        }
        try:
            return codec_dict.get(self.reload_tracefile('rtp')[0].rtp.p_type)
        except:
            self.log.debug(traceback.print_exc())
            return ''
        pass
    
    def get_rtp_ssrc(self, sender_ip):
        '''
        按照传入的发送方地址获取rtp的ssrc参数
        Args:
            sender_ip: 发送方地址

        Returns:
            ssrc字段值或none
        '''
        try:
            return self.reload_tracefile('rtp&&ip.src==' + sender_ip)[0].rtp.ssrc
        except:
            self.log.debug(traceback.print_exc())
            return None
    
    def check_rtcp_ssrc(self, caller_ip, callee_ip, rtcp_type='rtcp'):
        '''
        校验rtcp中包含的主叫、被叫ssrc正确
        Args:
            sender_ip: 通话主叫方ip
            recver_ip: 通话被叫方ip
        Returns:
            主被叫rtp的ssrc都与rtcp包中一致时，返回True，否则False
        '''
        '''
        （2）sender SSRC与待测设备所发送RTP的SSRC值一致;
        （3）sorce->identifier与辅助设备所发送RTP的SSRC值一致;
        （4）SDES报文里的identifier与待测设备所发送RTP的SSRC值一致;
        '''
        (caller_rtcp_sender_ssrc, callee_rtcp_source_ssrc, caller_ID_ssrc) = ('', '', '')
        (caller_rtp_ssrc, callee_rtp_ssrc, caller_rtp_ssrc) = ('', '', '')
        
        try:
            caller_rtp_ssrc = self.get_rtp_ssrc(caller_ip)
            callee_rtp_ssrc = self.get_rtp_ssrc(callee_ip)
            caller_rtcp_sender_ssrc = ''
            callee_rtcp_source_ssrc = ''
            caller_ID_ssrc = ''
            tmp_pkt = self.reload_tracefile("(rtcp)&&ip.src==" + caller_ip)[0]
            if rtcp_type == 'rtcp':
                caller_rtcp_sender_ssrc = tmp_pkt.rtcp.senderssrc
                callee_rtcp_source_ssrc = tmp_pkt.rtcp.ssrc_identifier
                caller_ID_ssrc = tmp_pkt.layers[4].ssrc_identifier
            elif rtcp_type == 'rtcp_xr':
                caller_rtcp_sender_ssrc = tmp_pkt.rtcp.senderssrc
                callee_rtcp_source_ssrc = tmp_pkt.layers[4].ssrc_identifier
                caller_ID_ssrc = tmp_pkt.rtcp.ssrc_identifier
            
            self.log.debug('''
                caller rtp ssrc: %s
                callee rtp ssrc: %s''' %
                           (caller_rtp_ssrc, callee_rtp_ssrc))
            self.log.debug('''
                sender SSRC: %s
                source-identifier: %s
                SDES identifier: %s
            ''' % (caller_rtcp_sender_ssrc, callee_rtcp_source_ssrc, caller_ID_ssrc))
        except:
            self.log.debug(traceback.print_exc())
        
        
        finally:
            return (caller_rtcp_sender_ssrc, callee_rtcp_source_ssrc, caller_ID_ssrc) == \
                   (caller_rtp_ssrc, callee_rtp_ssrc, caller_rtp_ssrc)
        pass
    
    def check_rtcp_icmp(self):
        '''rtcp选用disable模式，校验rtcp回复icmp'''
        try:
            tmp_pkt = self.reload_tracefile('rtcp')
            if tmp_pkt[0].rtcp and tmp_pkt[1].icmp:
                self.log.debug('icmp packet found after rtcp packet:')
                self.log.debug(tmp_pkt[1])
                return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        pass
    
    def check_rtcp_type(self, sender_ip, rtcp_type='rtcp'):
        '''
        rtcp_type为sender report(200)和SEDS(202)
        rtcp_xr_type为Extended report (RFC 3611) (207)、sender report(200)和SEDS(202)

        Args:
            sender_ip: rtcp包发送方
            rtcp_type: rtcp\rtcp_xr，以rfc 3611作为关键字区别

        Returns:
            bool
        '''
        target_string = 'RFC 3611'
        if rtcp_type == 'rtcp':
            try:
                return target_string not in str(self.reload_tracefile \
                                                    ('rtcp&&ip.src==' + sender_ip)[0].rtcp)
            except:
                self.log.debug(traceback.print_exc())
                return False
        
        elif rtcp_type == 'rtcp_xr':
            try:
                return target_string in str(self.reload_tracefile \
                                                ('rtcp&&ip.src==' + sender_ip)[0].rtcp)
            except:
                self.log.debug(traceback.print_exc())
                return False
    
    def check_rtcp_bye(self, sender_ip):
        '''
        检查发送方在通话结束时发出rtcp的goodbye消息
        Args:
            sender_ip: 发送方地址
        Returns:bool
        '''
        dis_filter = 'rtcp.pt == 203 && ip.src==' + sender_ip
        try:
            self.log.debug(self.reload_tracefile(dis_filter)[0])
            return True
        except:
            self.log.debug(traceback.print_exc())
            return False
        pass
    
    def check_crypto_header(self, switch_option=0) -> bool:
        '''
        # 1.当密钥生存周期开启时，在200OK的SIP信令中可以看到
        # a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:2M+DBz/Zn/eMBeKD3x94tlN4uujXSNSSyOPkIPRr|2^32
        # 2.当密钥生存周期关闭时，在200OK的SIP信令中可以看到
        # a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dMUTk2cndmlHXs40Q3RR/vz2Cy5hX4lXW/MjltcC
        Args:
            switch_option: 0-no,1-yes

        Returns:
            bool
        '''
        dis_filter = 'sip.Method=="INVITE"'
        try:
            if switch_option == 0:
                return '2^32' not in str(self.reload_tracefile(dis_filter)[0].sip)
            elif switch_option == 1:
                return '2^32' in str(self.reload_tracefile(dis_filter)[0].sip)
        except:
            self.log.debug(traceback.print_exc())
            return False


if __name__ == '__main__':
    log = Log_to_file('test')
    # from DATA.config_data_reader import sip_account_info
    #
    # openser_caller_num = sip_account_info.get('openser_caller_num')
    # openser_callee_num_auto = sip_account_info.get('openser_callee_num')
    
    pkt = Trace_Analysist('/home/auto_test/Desktop/test_010_case1700_keep_alive_interval.pcap', '', log)
    
    # print(pkt.check_rtcp_ssrc(caller_ip='192.168.85.192', callee_ip='192.168.85.197',
    #                           rtcp_type='rtcp_xr'))
    #
    # print(pkt.check_rtp_dtmf_payload('120'))
    # print(pkt.check_dtmf_msg('192.168.85.192', '192.168.85.170', '1', 1))
    dis_filter = ''.join(('classicstun && ip.dst==192.168.84.22'))
    print(pkt.reload_tracefile(dis_filter)[0].udp.dstport)
    print(pkt.get_keep_alive_interval('192.168.84.22'))
    
    # print(pkt.reload_tracefile('sip.Method=="INFO"')[0].sip)
    # print(pkt.reload_tracefile('rtcp&&ip.src==192.168.85.192')[0].layers[4])
    # print(pkt.reload_tracefile('rtcp&&ip.src==192.168.85.192')[0].layers[4].ssrc_identifier)
    #
    # print(dir(pkt.reload_tracefile('rtcp&&ip.src==192.168.85.192')[0].rtcp))
    
    # print(dir(pkt.reload_tracefile('rtcp')[1].icmp))
    
    # print('SRTP Encrypted Payload' in str(pkt.reload_tracefile('rtp')[0].rtp))
    
    # tmp_dict=dict(str(pkt.reload_tracefile('sip')[0].sip))
    # print(pkt.reload_tracefile('sip')[0].sip.sdp_media_format)
    # print(pkt.reload_tracefile('sip')[0].sip.sdp_media_attribute_field)
    
    # print(pkt.reload_tracefile('sip')[0].sip)
    
    # print((pkt.reload_tracefile('sip.Session-Expires contains "refresher"')[0].sip.session_expires))
    
    # print(dir(pkt.reload_tracefile('classicstun')[0].frame_info))
    
    # print(pkt.trace_pkt[28].sip)
    
    # self.check_call_established(conf_holder, callee_1),
    # self.check_hold_call(conf_holder, callee_1),
    # self.check_call_established(conf_holder, callee_2),
    # self.check_recover_call(conf_holder, callee_1)
    
    # print(pkt.check_call_established(openser_caller_num[0], openser_callee_num_auto[0]))
    # print(pkt.check_call_established(openser_caller_num[0], openser_callee_num_auto[1]))
    # print(pkt.check_call_established(openser_caller_num[0], openser_callee_num_auto[2]))
    # print(pkt.check_call_established(openser_caller_num[0], openser_callee_num_auto[3]))
    # print(pkt.check_call_established(openser_caller_num[0], openser_callee_num_auto[4]))
    
    # chk_point_3 = pkt.check_t_conf(openser_caller_num[0], openser_callee_num_auto[0],
    #                                openser_callee_num_auto[1])
    # #
    # print('final=',chk_point_3)
    # chk_point_4 = pkt.check_call_established(openser_caller_num[1], openser_callee_num_auto[2])
    # chk_point_5 = pkt.check_refer_correct(refered_by='2602',
    #                                       refer_to='2603')
    # print(chk_point_5)
    # chk_point_6 = pkt.check_call_established(openser_callee_num_auto[2], openser_caller_num[2])
    
    # chk_point_4 = pkt.check_call_established(openser_caller_num[1], openser_callee_num_auto[2])
    # print(chk_point_4)
    #
    # chk_point_5 = pkt.check_call_established(openser_caller_num[1], openser_caller_num[2])
    # print(chk_point_5)
    #
    # chk_point_6 = pkt.check_refer_correct(refered_by=openser_caller_num[1],
    #                                       refer_to=openser_callee_num_auto[2])
    # print(chk_point_6)
    #
    # chk_point_7 = pkt.check_recover_call(openser_callee_num_auto[2], openser_caller_num[2])
    # print(chk_point_7)
