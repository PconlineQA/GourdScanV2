#!/usr/bin/python3
# -*- coding: utf-8 -*-
from socket import *
import json
import time
import threading
from lib import config
from web.handlers.main import PortScanHandler

lock = threading.Lock()
openNum = 0
threads = []

def portScanner(host, port):
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((host, port))
        lock.acquire()
        lock.release()
        s.close()
        return {"status": "open"}
    except:
        return {"status": "close"}
        pass

def scan_start():
    cam_server = [
        {
            "ip": config.load()["ip"].encode('raw_unicode_escape'),
            "port": int(config.load()["port"]),
            "type": "server"
        }, {
            "ip": config.load()["redis_host"].encode('raw_unicode_escape'),
            "port": int(config.load()["redis_port"]),
            "type": "redis"
        }, {
            "ip": config.load()["tornado_address"].encode('raw_unicode_escape'),
            "port": int(config.load()["tornado_port"]),
            "type": "proxy"
        }, {
            "ip": config.load_rule()["sqlmap_api"].split(':')[1].split('//')[1].encode('raw_unicode_escape'),
            "port": int(config.load_rule()["sqlmap_api"].split(':')[2]),
            "type": "sqlmap"
        }, {
            "ip": config.load()["appscan_address"].encode('raw_unicode_escape'),
            "port": int(config.load()["appscan_port"]),
            "type": "appscan"
        }
    ]
    while True:
        try:
            setdefaulttimeout(1)
            result = []
            for i in cam_server:
                if i['ip'] == "0.0.0.0":
                    i['ip'] = "127.0.0.1"
                result.append(dict(i.items()+portScanner(i['ip'], i['port']).items()))
            # scan status
            result.append(dict({
                "type": "scan",
                "status": ("open" if (config.load()['scan_stat'].lower() == "true") else "close")
            }))
            # print result
            for u in PortScanHandler.users:
                u.write_message('{"data":' + str(result).replace("'", '"') + ',"msg":"系统-消息","code":2}')
            time.sleep(5)
        except Exception, e:
            print(str(e))
            time.sleep(5)
    return
