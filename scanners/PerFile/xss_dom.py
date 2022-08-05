#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/15 3:52 PM
# @Author  : w8ay
# @File    : xss.py

import asyncio

from pyppeteer import launch
from config import CHROMIUM

from lib.core.enums import VulType
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):

    name = 'XSS语义化探测插件'

    def init(self):
        self.result = ResultObject(self)
        self.result.init_info(self.requests.url, self.requests.params, "XSS脚本注入", VulType.XSS)

    def audit(self):
        # return
        # self.resp_str = self.response.text
        self.init()
        iterdatas = self.generateItemdatas()
        for origin_dict, positon in iterdatas:
            if "POST" in positon:
                return
            else:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                asyncio.get_event_loop().run_until_complete(self.browers_check())

    async def browers_check(self):
        browser = await launch(headless=True, executablePath=CHROMIUM, options={"handleSIGINT": False,"handleSIGTERM": False,"handleSIGHUP": False})
        page = await browser.newPage()
        await page.setCookie(self.requests.do_cookies)

        if "#" in self.requests.url:
            payload = "test/<test4dom>test4dom_xss"
        else:
            payload = "#test/<test4dom>test4dom_xss"
        url = self.requests.url + payload
        await page.goto(url)
        await page.waitFor(5000)

        resp = await page.content()

        await asyncio.sleep(1)

        await page.close()
        await browser.close()

        if "<test4dom>test4dom_xss</test4dom>" in resp:
            result = self.new_result()
            result.init_info(self.requests.url, self.requests.params,"DOM XSS 漏洞", VulType.XSS)
            self.result.add_detail("可自定义任意标签事件", url, resp,
                                   "可以自定义类似 '<test4dom>test4dom_xss'的标签事件,注意返回格式为:" + "<test4dom>test4dom_xss</test4dom>",
                                   "", payload,
                                   "")
            self.success(result)
            return True