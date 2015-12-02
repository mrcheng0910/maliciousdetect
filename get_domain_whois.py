#!/usr/bin/python
# encoding:utf-8
"""
得到白名單中域名的whois的信息
使用了gevent多線程，加快訪問速度，目前線程爲10

"""
import re
import gevent
from gevent import socket
from random import choice
from urlparse import urlparse
from top_whois_server_config import TLDs  # 获得顶级域名域名WHOIS服务器列表
from sql_command import Database
from whois_server_manage import *

THREADNUM = 5


def extract_domain(url=''):
    """
    Extracts domain from url,eg.,http://www.baidu.com/index.html ---> www.baidu.com

    Args:
        url: The url will be extracted

    Returns:
        domain: The domain of the input url

    Raise:
        if url's format is wrong

    """

    if not url:
        print 'The url is empty'
        return

    domain = ''
    # 添加http头部
    scheme = re.compile("https?\:\/\/", re.IGNORECASE)
    if scheme.match(url) is None:
        url = "http://" + url
    parsed = urlparse(url)  # urlparse格式化
    domain = parsed.netloc  # 提取域名
    if not domain:
        print 'Wrong url format'
        sys.exit()  # 空则结束

    return domain


class domain_info:

    """
    域名信息类，包括网址、域名、WHOIS服务器等信息
    """

    def __init__(self, url=''):

        self.url = url
        self.domain = ''
        self.query_domain = ''
        self.top_whois_server = ''  # 顶级WHOIS服务器
        self.sec_whois_server = ''  # 二级WHOIS服务器
        self.real_sec_whois_server = ''  # 真实查询WHOIS服务器
        self.reg_name = ''   # 注册姓名
        self.reg_phone = ''  # 注册电话
        self.reg_email = ''  # 注册邮箱
        self.detail = ''     # detail

        self.domain = extract_domain(self.url)  # 提取域名
        self.achieve_top_whois_server()  # 获得顶级WHOIS服务器

    def achieve_top_whois_server(self):
        """
        根据顶级域名WHOIS信息注册商列表，获得顶级WHOIS服务器
        """
        if not self.domain:
            return

        PointSplitResult = self.domain.split('.')
        domain_length = len(PointSplitResult)
        top_level_domain = '.' + PointSplitResult[-1]

        if domain_length <= 2:
            if TLDs.has_key(top_level_domain.lower()):
                self.top_whois_server = TLDs[top_level_domain.lower()]
                self.query_domain = self.domain
            else:
                print "没有该顶级域名WHOIS注册商，请联系管理员"
                return

        second_level_domain = '.' + PointSplitResult[-2]
        host = second_level_domain + top_level_domain

        if TLDs.has_key(host.lower().strip()):
            self.top_whois_server = TLDs[host.lower()]
            self.query_domain = PointSplitResult[-3] + host.lower()

        elif TLDs.has_key(top_level_domain.lower()):
            self.top_whois_server = TLDs[top_level_domain.lower()]
            self.query_domain = PointSplitResult[-2] + top_level_domain.lower()
        else:
            print '没有该顶级域名WHOIS注册商，请联系管理员'
            return

    def domain_whois(self):
        """
        获得二级域名WHOIS信息注册商信息
        """
        data_result = ''

        if str(self.top_whois_server) == "['whois.verisign-grs.com', 'whois.crsnic.net']":

            data_result = self.get_socket('top')

            if not data_result:
                print '没有数据返回'
                return

            domain_info = general_manage(data_result)
            if domain_info:
                self.update(domain_info)
                return

            sec_whois_server = get_sec_server(data_result, self.query_domain)
            if sec_whois_server:
                self.sec_whois_server = sec_whois_server
                data_result = self.get_socket('second')
                if data_result:
                    domain_info = general_manage(data_result)
                    if domain_info:
                        self.update(domain_info)
                    return
                else:
                    return

            xxx_info = xxx_manage(data_result)
            if xxx_info:
                data_result = self.get_socket('top', False)
                sec_whois_server = get_sec_server(
                    data_result, self.query_domain)
                if sec_whois_server:
                    self.sec_whois_server = sec_whois_server
                    # print sec_whois_server
                    data_result = self.get_socket('second')
                    if data_result:
                        domain_info = general_manage(data_result)
                        print domain_info
                        if domain_info:
                            self.update(domain_info)
                            return
            nomatch = no_match(data_result)
            if nomatch:
                domain_info = nomatch.get('reg_name', '')
                self.update(domain_info)
                return

        elif str(self.top_whois_server) == "['whois.nic.me', 'whois.meregistry.net']":
            data_result = self.get_socket('top')
            if not data_result:
                print '没有数据返回'
                return
            domain_info = general_manage(data_result)
            if domain_info:
                self.update(domain_info)
        # ua
        elif str(self.top_whois_server) == "whois.ua":
            self.query_domain = self.domain
            data_result = self.get_socket('top')
            if data_result:
                domain_info = ua_manage(data_result)
                self.update(domain_info)
        # ie
        elif str(self.top_whois_server) == "['whois.iedr.ie', 'whois.domainregistry.ie']":
            data_result = self.get_socket('top')
            if data_result:
                domain_info = ie_manage(data_result)
                self.update(domain_info)
        # es
        elif str(self.top_whois_server) == "whois.nic.es":
            data_result = self.get_socket('top')
            if data_result:
                domain_info = es_manage(data_result)
                self.update(domain_info)
        # ru
        elif str(self.top_whois_server) == "['whois.ripn.ru', 'whois.ripn.net']":
            data_result = self.get_socket('top')
            if data_result:
                domain_info = ru_manage(data_result)
                self.update(domain_info)
        # us,info,org
        elif (str(self.top_whois_server) == "['whois.pir.org', 'whois.publicinterestregistry.net']") or \
             (str(self.top_whois_server) == "whois.nic.us") or (str(self.top_whois_server) == "['whois.afilias.info', 'whois.afilias.net']"):
            data_result = self.get_socket('top')
            # print data_result
            if not data_result:
                print '没有数据返回'
                return
            domain_info = general_manage(data_result)
            if domain_info:
                self.update(domain_info)
        # to,tc
        elif (str(self.top_whois_server) == "whois.tonic.to") or (str(self.top_whois_server) == "whois.nic.es") or \
                (str(self.top_whois_server) == 'whois.eu') or (str(self.top_whois_server) == "whois.nic.tr") or \
                (str(self.top_whois_server) == "['whois.srs.net.nz', 'whois.domainz.net.nz']") or str(self.top_whois_server) == "whois.denic.de":
            data_result = self.get_socket('top')

            if data_result:
                domain_info = nomatch_manage(data_result)
                self.update(domain_info)
        # co_za
        elif str(self.top_whois_server) == "whois.registry.net.za":

            data_result = self.get_socket('top')

            if data_result:

                domain_info = co_za_manage(data_result)
                self.update(domain_info)

        elif str(self.top_whois_server) == "whois.audns.net.au":
            self.query_domain = self.domain
            data_result = self.get_socket('top')
            if data_result:

                domain_info = au_manage(data_result)
                self.update(domain_info)
        elif str(self.top_whois_server) == "whois.nic.cl":
            self.query_domain = self.domain
            data_result = self.get_socket('top')
            if data_result:
                domain_info = cl_manage(data_result)
                self.update(domain_info)
        elif str(self.top_whois_server) == "whois.nic.br":
            self.query_domain = self.domain
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = nomatch_manage(data_result)
                self.update(domain_info)

        #biz ,mobi
        elif (str(self.top_whois_server) == "whois.dotmobiregistry.net") or (str(self.top_whois_server) == "whois.neulevel.biz") or \
             (str(self.top_whois_server) == 'whois.nic.xyz'):

            data_result = self.get_socket('top')
            if not data_result:
                print '没有数据返回'
                return
            domain_info = general_manage(data_result)
            if domain_info:
                self.update(domain_info)

        elif str(self.top_whois_server) == "whois.amnic.net":

            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = am_manage(data_result)
                self.update(domain_info)
        # as
        elif str(self.top_whois_server) == "whois.nic.as":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = as_manage(data_result)
                self.update(domain_info)
        elif str(self.top_whois_server) == "whois.adamsnames.tc" or str(self.top_whois_server) == "['whois.registrypro.pro', 'whois.registry.pro']" or \
                str(self.top_whois_server) == "['whois.inregistry.net', 'whois.registry.in']":
            data_result = self.get_socket('top')
            # print data_result
            if not data_result:
                print '没有数据返回'
                return
            domain_info = general_manage(data_result)
            if domain_info:
                self.update(domain_info)
        # cn
        elif str(self.top_whois_server) == "['whois.cnnic.cn', 'whois.cnnic.net.cn']":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = cn_manage(data_result)
                self.update(domain_info)
        # it
        elif str(self.top_whois_server) == "whois.nic.it":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = it_manage(data_result)
                self.update(domain_info)
        # pl
        elif str(self.top_whois_server) == "whois.dns.pl":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = pl_manage(data_result)
                self.update(domain_info)
        elif str(self.top_whois_server) == "whois.cira.ca":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = ca_manage(data_result)
                self.update(domain_info)

        # ae
        elif str(self.top_whois_server) == "whois.aeda.net.ae":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = ae_manage(data_result)
                self.update(domain_info)
        # ro
        elif str(self.top_whois_server) == "whois.rotld.ro":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = ro_manage(data_result)
                self.update(domain_info)
        # tw
        elif str(self.top_whois_server) == "whois.twnic.net.tw":
            self.query_domain = self.domain
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = tw_manage(data_result)
                self.update(domain_info)
        # uk
        elif str(self.top_whois_server) == 'whois.nic.uk':
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = uk_manage(data_result)
                self.update(domain_info)

    def get_socket(self, level='', flag=True):
        """
        与域名WHOIS信息注册商进行连接查询,level表示顶级或者二级查询，flag表示是否需要添加"="标志
        """
        # flag标志位
        if flag:
            query_domain = self.query_domain  # 无flag

        else:
            query_domain = '=' + self.query_domain  # 有'='

        # 顶级、二级域名查询
        if level == 'top':
            if type(self.top_whois_server) == list:  # 若WHOIS注册商为列表，则随机选择一个
                HOST = choice(self.top_whois_server)

            else:
                HOST = self.top_whois_server
        elif level == 'second':
            HOST = self.sec_whois_server

        data_result = ''
        PORT = 43
        BUFSIZ = 1024
        ADDR = (HOST, PORT)
        EOF = "\r\n"
        data_send = query_domain + EOF
        try:
            tcpCliSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # tcpCliSock.settimeout(8)
            tcpCliSock.connect(ADDR)
            tcpCliSock.send(data_send)
        except:
            print 'Socket Wrong'
            return False
        while True:
            try:
                data_rcv = tcpCliSock.recv(BUFSIZ)
            except:
                print 'receive Failed'
                tcpCliSock.close()
                return
            if not len(data_rcv):
                tcpCliSock.close()
                # print data_result
                return data_result  # 返回查询结果
            data_result = data_result + data_rcv

    def update(self, domain_info):

        self.reg_name = domain_info.get('reg_name', '')
        self.reg_email = domain_info.get('reg_email', '')
        self.reg_phone = domain_info.get('reg_phone', '')
        self.detail = domain_info.get('detail', '')


def get_domain():

    exist_domain = []
    existe_domain_temp = ()
    check_domain_list_temp = ()
    check_domain_list = []

    db = Database()
    existe_domain_temp = db.existed_white_domain()
    if existe_domain_temp:
        exist_domain = [i[0] for i in existe_domain_temp]

    check_domain_list_temp = db.get_check_domain()
    if check_domain_list_temp:
        check_domain_list = [i[0] for i in check_domain_list_temp]
    db.close_db()
    # print len(list(set(domain_list).difference(set(exist_domain))))
    return list(set(exist_domain).difference(set(check_domain_list)))


def check_domain(url=''):
    print url
    query_domain = ''
    query_domain = domain_info(url)

    if not query_domain.query_domain:
        return
    query_domain.domain_whois()
    # print query_domain.domain,query_domain.reg_email,query_domain.reg_name
    return query_domain


def main():

    domain_list = []
    domain_list = get_domain()

    total_domain_count = len(domain_list)
    count = 0
    print total_domain_count
    while count * THREADNUM < total_domain_count:
        domains = []
        db = Database()
        domains = domain_list[count * THREADNUM: (count + 1) * THREADNUM]
        jobs = [gevent.spawn(check_domain, str(domain.strip()))
                for domain in domains]

        gevent.joinall(jobs, timeout=10)
        count = count + 1

        db.insert_white_whois(jobs)
        db.close_db()

if __name__ == '__main__':

    main()
