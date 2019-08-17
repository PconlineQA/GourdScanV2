#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import base64
import urllib
import threading
import time
import tornado.web
import requests

from lib.redisopt import conn
from lib import out
from lib import scan
from lib import secure
from lib import config
from lib import session
from proxy import pyscapy, mix_proxy, proxy_io
from web.handlers.base import BaseHandler, authenticated
from tornado.websocket import WebSocketHandler

class PageNotFoundHandler(tornado.web.RequestHandler):

    def get(self):
        return self.render("404.html")


class LogoutHandler(BaseHandler):

    @authenticated
    def get(self):
        session.destroy(self.get_cookie("ysrc_token"))
        self.set_header("Location", "/")
        self.set_status(302)
        return


class LoginHandler(tornado.web.RequestHandler):

    def get(self):
        return self.render("login.html")

    def post(self):
        account = secure.clear(self.get_argument("account"))
        password = secure.clear(self.get_argument("password"))
        if account == config.load()['account'] and password == config.load()['password']:
            cookie = session.new(self.request.remote_ip)
            self.set_cookie("ysrc_token", cookie, expires_days=int(config.load()["session_expires_time"]))
            session.update(cookie)
            self.set_header("Location", "/")
            self.set_status(302)
            return
        else:
            location = "/login"
            content = "Something wrong with you account or password!"
            return self.render("302.html", location=location, content=content)


class IndexHandler(BaseHandler):

    @authenticated
    def get(self):
        waiting = conn.lrange("waiting", 0, 15)
        running = conn.lrange("running", 0, 15)
        finished = conn.lrange("finished", 0, 15)
        norunning = conn.lrange("norunning", 0, 15)
        vulnerable = conn.lrange("vulnerable", 0, 15)
        stats_all = {}
        for i in [waiting, running, finished, norunning, vulnerable]:
            for reqhash in i:
                try:
                    decode_results = json.loads(base64.b64decode(conn.hget("results", reqhash)))
                except:
                    decode_results = {'stat':0}
                stats = ['success', 'info', 'warning', "danger"]
                stat = decode_results['stat']
                stat = stats[stat]
                stats_all[reqhash] = stat
        self.render("index.html", waiting_num=conn.llen("waiting"), running_num=conn.llen("running"), finished_num=conn.llen("finished"), norunning_num=conn.llen("norunning"), vulnerable_num=conn.llen("vulnerable"), waiting=waiting, running=running, finished=finished, norunning=norunning, vulnerable=vulnerable, time=config.load()["flush_time"], stats_all=stats_all)
        return


class ConfHandler(BaseHandler):

    @authenticated
    def get(self):
        return self.render("config.html", config = config.load())

    @authenticated
    def post(self):
        conf_all = config.load()
        for i in self.request.body.split("&"):
            para = secure.clear(urllib.unquote(i.split("=", 1)[0]))
            value = secure.clear(urllib.unquote(i.split("=", 1)[1]))
            if para in conf_all.keys():
                conf_all[para] = value
        config.update(conf_all)
        return self.render("config.html", config=config.load())


class ScanConfigHandler(BaseHandler):

    @authenticated
    def get(self):
        start = {}
        rule = ["sqlireflect", "sqlitime", "sqlmap", "xpath", "xss", "lfi", "ldap", "sqlibool"]
        for i in rule:
            start[i + "_true"] = ""
            start[i + "_false"] = "checked"
        for i in config.load_rule()["scan_type"]:
            start[i + "_true"] = "checked"
            start[i + "_false"] = ""
        rules = {}
        for i in rule:
            rules[i] = config.rule_read(i)
        return self.render("scan_config.html", config=config.load(), start=start, rules=rules, scan_stat=config.load()['scan_stat'], sqlmap_api=config.load_rule()['sqlmap_api'])

    @authenticated
    def post(self):
        start = []
        rule = ["sqlireflect", "sqlitime", "sqlmap", "xpath", "xss", "lfi", "ldap", "sqlibool"]
        conf = config.load_rule()
        for i in rule:
            on = self.get_argument(i + "_start")
            if on == "true":
                start.append(i)
            rules = self.get_argument(i + "_rule")
            config.rule_write(i, rules)
            if i == "sqlmap":
                address = self.get_argument("sqlmap_api")
                conf['sqlmap_api'] = address
        conf['scan_type'] = start
        config.update_rule(conf)
        return self.write(out.jump("/scan_config"))


class ScanStatHandler(BaseHandler):

    @authenticated
    def get(self):
        stat = secure.clear(self.get_argument("stat"))
        config_all = config.load()
        config_all['scan_stat'] = stat
        config.update(config_all)
        if stat.lower() == "true":
            thread = threading.Thread(target=scan.scan_start, args=())
            thread.setDaemon(True)
            thread.start()
            from lib import portscan
            thread = threading.Thread(target=portscan.scan_start, args=())
            thread.setDaemon(True)
            thread.start()
        return self.write(out.jump("/scan_config"))


class ReqHandler(BaseHandler):

    @authenticated
    def get(self):
        try:
            request_hash = self.get_argument("hash")
            request = json.loads(base64.b64decode(conn.hget("request", request_hash)))
            if not conn.hget("results", request_hash):
                results = {}
                stat = "success"
            else:
                results = json.loads(base64.b64decode(conn.hget("results", request_hash)))
                stat = results['stat']
                stats = ['success', 'info', 'warning', "danger"]
                stat = stats[stat]
                if results['stat'] == 0:
                    results = {}
                else:
                    del results['stat']
                    for rule in results.keys():
                        if results[rule]['stat'] == 0:
                            del results[rule]
                        else:
                            results[rule]['stat'] = stats[results[rule]['stat']]
                            messages = []
                            for message in results[rule]['message']:
                                if message != "":
                                    messages.append(message)
                                results[rule]['message'] = messages
                #split the url in 80 chars
            url = request['url']
            request['url_encode'] = ""
            for i in range(len(url)/80+1):
                request['url_encode'] += url[i*80:i*80+80] + "\n"
            return self.render("req.html", request=request, results=results, stat=stat)
        except Exception, e:
            out.error(str(e))
            return self.write(str(e))


class ListHandler(BaseHandler):

    @authenticated
    def get(self):
        list_type = self.get_argument("type")
        try:
            start = int(self.get_argument("start"))
        except:
            start = 0
        page_num = int(config.load()['page_num'])
        length = conn.llen(list_type)
        last = start + page_num - 1
        page_now = start / page_num + 1
        end_page = -1 * ((-1 * length) / page_num)
        end_num = end_page * page_num - page_num
        if page_now - 2 >= 1:
            pages_first = page_now - 2
        else:
            pages_first = 1
        if page_now + 2 <= end_page:
            pages_last = page_now + 2
        else:
            pages_last = end_page
        pages = range(pages_first, pages_last + 1)
        content = conn.lrange(list_type, start, last)
        req_content = {}
        lost_content= []
        for reqhash in content:
            try:
                decode_content = json.loads(base64.b64decode(conn.hget("request", reqhash)))
            except Exception,e:
                lost_content.append(reqhash)
                continue
            try:
                decode_results = json.loads(base64.b64decode(conn.hget("results", reqhash)))
            except:
                decode_results = {'stat': 0}
            req_content[reqhash] = decode_content['method'] + "|" + decode_content['url']
            #split the url in 80 chars
            req_content[reqhash] += "|"
            for i in range(len(req_content[reqhash].split("|")[1])/80+1):
                req_content[reqhash] += req_content[reqhash].split("|")[1][i*80:i*80+80] + "\n"
            stats = ['success', 'info', 'warning', "danger"]
            stat = decode_results['stat']
            stat = stats[stat]
            req_content[reqhash] += "|" + stat
            req_content[reqhash] += "|" + time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(decode_content['time']))
        for i in lost_content:
            content.remove(i)
        return self.render("list.html", page_now=page_now, page_num=page_num, pages=pages, content=content, list_type=list_type, length=length, req_content=req_content, end_num=end_num)

class AppScanHandler(BaseHandler):

    @authenticated
    def get(self):
        list_type = self.get_argument("type")
        scan_host = self.get_argument("host")
        start = 0
        length = conn.llen(list_type)
        content = conn.lrange(list_type, start, length)
        proxy_addr = config.load()['appscan_address']+":"+config.load()['appscan_port']
        proxies = {"http": "http://"+proxy_addr, "https": "http://"+proxy_addr, }
        print proxies
        for reqhash in content:
            try:
                request = json.loads(base64.b64decode(conn.hget("request", reqhash)))
            except Exception,e:
                continue
            if scan_host not in request['url']:
                continue
            try:
                if request['method'] == 'GET':
                    res = requests.get(url=request['url'], headers=request['headers'], verify=False, proxies=proxies, timeout=10)
                elif request['method'] == 'POST':
                    res = requests.post(url=request['url'], headers=request['headers'], data=request['postdata'], verify=False, proxies=proxies, timeout=10)
            except Exception, e:
                print e
                continue
        return self.write(out.alert("set success!", "/list?type="+list_type))


class ProxyHandler(BaseHandler):

    @authenticated
    def get(self):
        proxy_type = self.get_argument("type")
        conf = {}
        if proxy_type == "mix_proxy":
            conf['mix_addr'] = config.load()['mix_addr']
            conf['mix_port'] = config.load()['mix_port']
            stat = config.load()['mix_stat']
            try:
                start_stat = self.get_argument("stat")
                start_conf = config.load()
                start_conf['mix_stat'] = start_stat
                config.update(start_conf)
                if start_stat.lower() == "true":
                    thread = threading.Thread(target=mix_proxy.main)
                    thread.setDaemon(True)
                    thread.start()
                else:
                    secure.kill(config.load()['mix_addr'], int(config.load()['mix_port']), "GE")
                return self.write(out.jump("/proxy?type=" + proxy_type))
            except:
                pass
        elif proxy_type == "scapy":
            conf['scapy_out'] = config.load()['scapy_out']
            conf['scapy_network_card'] = config.load()['scapy_network_card']
            stat = config.load()['scapy_stat']
            try:
                start_stat = secure.clear(self.get_argument("stat"))
                start_conf = config.load()
                start_conf['scapy_stat'] = start_stat
                config.update(start_conf)
                if start_stat.lower() == "true":
                    thread = threading.Thread(target=pyscapy.main)
                    thread.setDaemon(True)
                    thread.start()
                return self.write(out.jump("/proxy?type=" + proxy_type))
            except:
                pass
        elif proxy_type == "tornado":
            conf['tornado_address'] = config.load()['tornado_address']
            conf['tornado_port'] = config.load()['tornado_port']
            stat = config.load()['tornado_stat']
            try:
                start_stat = secure.clear(self.get_argument("stat"))
                start_conf = config.load()
                start_conf['tornado_stat'] = start_stat
                config.update(start_conf)
                if start_stat.lower() == "true" and config.load()['tornado_run_stat'] == 'false':
                    thread = threading.Thread(target=proxy_io.main)
                    thread.setDaemon(True)
                    thread.start()
                    start_conf = config.load()
                    start_conf['tornado_run_stat'] = 'true'
                    config.update(start_conf)
                return self.write(out.jump("/proxy?type=" + proxy_type))
            except:
                pass
        else:
            return self.write(out.jump("/"))
        return self.render("proxy.html", proxy_type=proxy_type, conf=conf, stat=stat)

    @authenticated
    def post(self):
        proxy_type = self.get_argument("type")
        if proxy_type == "mix_proxy":
            conf = config.load()
            conf["mix_addr"] = secure.clear(self.get_argument("mix_addr"))
            conf["mix_port"] = secure.clear(self.get_argument("mix_port"))
            config.update(conf)
        elif proxy_type == "scapy":
            conf = config.load()
            conf['scapy_out'] = secure.clear(self.get_argument('scapy_out'))
            conf['scapy_network_card'] = self.get_argument('scapy_network_card')
            config.update(conf)
        elif proxy_type == "tornado":
            conf = config.load()
            conf['tornado_address'] = secure.clear(self.get_argument('tornado_address'))
            conf['tornado_port'] = secure.clear(self.get_argument('tornado_port'))
            config.update(conf)
        return self.write(out.jump("/proxy?type=" + proxy_type))


class DelHandler(BaseHandler):

    @authenticated
    def get(self):
        del_type = self.get_argument("type")
        if self.request.arguments.has_key("hash"):
            request_hash = self.get_argument("hash")
            conn.hdel("request", request_hash)
            for del_type1 in ['waiting', 'finished', 'running', 'vulnerable']:
                conn.lrem(del_type1, 0, request_hash)
            try:
                conn.hdel("results", request_hash)
            except:
                pass
        else:
            if del_type in ['waiting', 'finished', 'running', 'vulnerable']:
                conn.delete(del_type)
            elif del_type == "flushdb":
                conn.flushdb()
                return self.write(out.jump("/"))
        return self.write(out.jump("/list?type=" + del_type))

class RetryHandler(BaseHandler):

    @authenticated
    def get(self):
        retry_type = self.get_argument("type")
        if self.request.arguments.has_key("hash"):
            request_hash = self.get_argument("hash")
            for del_type1 in ['finished', 'running', 'vulnerable']:
                conn.lrem(del_type1, 0, request_hash)
            try:
                conn.hdel("results", request_hash)
            except:
                pass
            conn.lpush('waiting', request_hash)
        else:
            if retry_type in ['finished', 'running', 'vulnerable']:
                while conn.llen(retry_type) > 0:
                    reqhash = conn.rpoplpush(retry_type, "waiting")
                    try:
                        conn.hdel("results", reqhash)
                    except:
                        pass
                    for del_type2 in ['finished', 'running', 'vulnerable']:
                        if retry_type != del_type2:
                            conn.lrem(del_type2, 0, reqhash)
                    try:
                        conn.hdel("results", reqhash)
                    except:
                        pass
                conn.delete(retry_type)
        return self.write(out.jump("/list?type=" + retry_type))


class ResetScanHandler(BaseHandler):

    @authenticated
    def get(self):
        if config.load()['scan_stat'].lower() == 'false':
            return self.write(out.jump("/"))
        stat = conn.rpoplpush("running", "waiting")
        while stat:
            stat = conn.rpoplpush("running", "waiting")
        return self.write(out.alert("reset success!", "/scan_stat?stat=true"))

class PortScanHandler(WebSocketHandler):

    users = set()  # 用来存放在线用户的容器

    def open(self):
        self.users.add(self)  # 建立连接后添加用户到容器中
        for u in self.users:  # 向已在线用户发送消息
            u.write_message('{"data":"","msg":"' + self.request.remote_ip + '-进入","code":1}')

    def on_message(self, message):
        for u in self.users:  # 向在线用户广播消息
            u.write_message('{"data":"' + message + '","msg":"' + self.request.remote_ip + '-消息","code":2}')

    def on_close(self):
        self.users.remove(self)  # 用户关闭连接后从容器中移除用户
        for u in self.users:
            u.write_message('{"data":"","msg":"' + self.request.remote_ip + '-离开","code":0}')

    def check_origin(self, origin):
        return True  # 允许WebSocket的跨域请求

