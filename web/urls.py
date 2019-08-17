#!/usr/bin/env python
#coding: utf-8
import handlers.main
import tornado.web

url_patterns =  [
    (r"^/$", handlers.main.IndexHandler),
    (r"^/login", handlers.main.LoginHandler),
    (r"^/logout", handlers.main.LogoutHandler),
    (r"^/index", handlers.main.IndexHandler),
    (r"^/config", handlers.main.ConfHandler),
    (r"^/proxy", handlers.main.ProxyHandler),
    (r"^/scan_config", handlers.main.ScanConfigHandler),
    (r"^/scan_stat", handlers.main.ScanStatHandler),
    (r"^/req", handlers.main.ReqHandler),
    (r"^/list", handlers.main.ListHandler),
    (r"^/to_appScan", handlers.main.AppScanHandler),
    (r"^/del", handlers.main.DelHandler),
    (r"^/retry", handlers.main.RetryHandler),
    (r"^/reset_scan", handlers.main.ResetScanHandler),
    (r"^/port_online", handlers.main.PortScanHandler),
    (r"^/.*", handlers.main.PageNotFoundHandler),
]


