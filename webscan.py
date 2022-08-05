import inspect
import os
import sys
import threading
import json

import requests
from colorama import deinit

from lib.controller.controller import start, task_push_from_name
from lib.core.enums import HTTPMETHOD
from lib.parse.parse_request import FakeReq
from lib.parse.parse_responnse import FakeResp
from lib.proxy.baseproxy import AsyncMitmProxy

from lib.parse.cmdparse import cmd_line_parser
from lib.core.data import logger, conf, KB
from lib.core.option import init


def version_check():
    if sys.version.split()[0] < "3.6":
        logger.error(
            "incompatible Python version detected ('{}'). To successfully run sqlmap you'll have to use version >= 3.6 (visit 'https://www.python.org/downloads/')".format(
                sys.version.split()[0]))
        sys.exit()


def modulePath():
    """
    This will get us the program's directory, even if we are frozen
    using py2exe
    """

    try:
        _ = sys.executable if hasattr(sys, "frozen") else __file__
    except NameError:
        _ = inspect.getsourcefile(modulePath)

    return os.path.dirname(os.path.realpath(_))


def main():
    # version_check()

    # init
    root = modulePath()
    cmdline = cmd_line_parser()
    init(root, cmdline)

    if conf.url or conf.url_file:
        urls = []
        body = ""
        cookie = {}
        if conf.url:
            urls.append(conf.url)
        if conf.url_file:
            urlfile = conf.url_file
            if not os.path.exists(urlfile):
                logger.error("File:{} don't exists".format(urlfile))
                sys.exit()
            with open(urlfile) as f:
                _urls = f.readlines()
            _urls = [i.strip() for i in _urls]
            urls.extend(_urls)
        # 数据格式为json文件。 解析json文件，进行扫描。默认支持 puppeteer 爬虫生成得json文件。
        for domain in urls:
            try:
                url = json.loads(domain)['url']
                method = json.loads(domain)['method']
                header = json.loads(domain)['headers']
                if "POST" in method:
                    body = json.loads(domain)['body']
                else:
                    cookie = json.loads(domain)['cookies'][0]
                req = requests.get(url)
            except Exception as e:
                logger.error("request {} faild,{}".format(url, str(e)))
                continue
            if "POST" in method:
                fake_req = FakeReq(url, header, method, body, cookie)
            else:
                fake_req = FakeReq(url, header, method, "", cookie)
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            task_push_from_name('loader', fake_req, fake_resp)
        start()
    elif conf.server_addr:
        KB["continue"] = True
        # 启动漏洞扫描器
        scanner = threading.Thread(target=start)
        scanner.setDaemon(True)
        scanner.start()
        # 启动代理服务器
        baseproxy = AsyncMitmProxy(server_addr=conf.server_addr, https=True)

        try:
            baseproxy.serve_forever()
        except KeyboardInterrupt:
            scanner.join(0.1)
            threading.Thread(target=baseproxy.shutdown, daemon=True).start()
            deinit()
            print("\n[*] User quit")
        baseproxy.server_close()


if __name__ == '__main__':
    main()
