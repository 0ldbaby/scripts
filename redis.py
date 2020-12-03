#! /usr/local/bin/python3

import sys
import getopt
import socket


# banner信息
def banner():
    print('\033[1;34m #' * 30, '\n',
          '\033[1;34m #' * 12, '\033[1;32m     Bin    ', '\033[1;34m #' * 12, '\n',
          '\033[1;34m #' * 30, '\033[0m\n',
          sep='')


# 使用规则
def usage():
    print('\033[1;35m-h: 查看帮助信息')
    print('-u: IP地址或类似1.1.1.1-255指定一个D段范围')
    print('-f: IP地址列表文件，一行为一个地址')
    print('-p: 端口，默认为6379')
    print('-s: 扫描类型：Redis, Telnet；默认Redis\033[0m\n')
    sys.exit()


# Redis未授权验证主方法
def redis_unauthored(ip, port):
    res = ''
    payload = '\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
    try:
        socket.setdefaulttimeout(10)
        s = socket.socket()
        s.connect((ip, port))
        s.sendall(payload.encode())
        recv = s.recv(1024).decode()
        if 'redis_version' in recv:
            res = 'success'
    except Exception as error:
        res = '错误：', error
    return res


# 生成IP地址列表，返回一个地址列表
def ip_list(ip):
    iplist = []
    if '-' in ip:
        address = ip.split('-', 1)
        init = address[0].split('.', -1)
        address_min = int(init[3])
        address_max = int(address[1])
        while address_min <= address_max:
            ip = "%s.%s.%s.%s" % (init[0], init[1], init[2], address_min)
            iplist.append(ip)
            address_min += 1
    else:
        iplist = [ip]
    return iplist


# 如果使用了文件，则通过该方法返回文件内的所有地址列表
def file_list(file):
    iplist = []
    f = open(file, 'r')
    for i in f:
        i = i.replace('\n', '')
        iplist.append(i)
    return iplist


# 定义输出格式，传入一个元组或者列表
def output(s, info):
    print('\033[1;35m Scan for %s \033[0m' % s, )
    print('+', '-' * 56, '+', sep='')
    print('|', ' ' * 5, 'IP', ' ' * 5, '|', ' ' * 5, 'PORT', ' ' * 5, '|', ' ' * 5, 'STATUS', ' ' * 5, '|')
    print('+', '-' * 56, '+', sep='')
    i = 0
    while i < len(info):
        print('|', ' ', info[i][0], ' ', '|', ' ' * 6, info[i][1], ' ' * 6, '|', ' ' * 6, info[i][2],
              ' ' * 6, '|', sep='')
        print('+', '-' * 56, '+', sep='')
        i += 1
    print('\033[1;33m[*] Shutting down...\033[0m')


def launcher(iplist, port, server):
    res = []
    port = port
    for li in iplist:
        ip = li
        status = redis_unauthored(ip, port)
        if 'success' in status:
            status = '\033[1;31mVulnerable\033[0m'
        else:
            status = str(status)
            status = '\033[1;32m%s\033[0m' % status
        res.append([ip, port, status])
    output(server, res)


def start(argv):
    ip = ''
    port = 6379
    server = 'Redis'
    if len(sys.argv) < 2:
        print('\033[1;32m -h 查看脚本帮助信息 \033[0m')
        sys.exit()
    try:
        banner()
        opts, args = getopt.getopt(argv, '-u:-f:-p:-s:-h')
    except Exception as error:
        print('参数错误：', error)
        sys.exit()

    for opt, arg in opts:
        if opt == '-u':
            ip = ip_list(arg)
        elif opt == '-f':
            ip = file_list(arg)
        elif opt == '-p':
            port = arg
        elif opt == '-s':
            server = arg
        elif opt == '-h':
            usage()
    launcher(ip, port, server)


if __name__ == '__main__':
    try:
        start(sys.argv[1:])
    except Exception as e:
        print('发生错误：', e)
