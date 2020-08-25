import base64
import hashlib
import hmac
import json
import os
import sys
from collections import OrderedDict

import click
import js2py
import netifaces
import requests

BASE_URL = "http://202.113.5.130"

xencode_src = 'function xEncode(r,n){function t(r,n){for(var t=r.length,o=[],e=0;e<t;e+=4)o[e>>2]=r.charCodeAt(e)|r.charCodeAt(e+1)<<8|r.charCodeAt(e+2)<<16|r.charCodeAt(e+3)<<24;return n&&(o[o.length]=t),o}if(""==r)return"";var o=t(r,!0),e=t(n,!1);e.length<4&&(e.length=4);for(var a,f,h,i=o.length-1,u=o[i],l=o[0],c=Math.floor(6+52/(i+1)),g=0;0<c--;){for(f=(g=g+-1640531527&-1)>>>2&3,h=0;h<i;h++)a=u>>>5^(l=o[h+1])<<2,a+=l>>>3^u<<4^g^l,a+=e[3&h^f]^u,u=o[h]=o[h]+a&-1;a=u>>>5^(l=o[0])<<2,a+=l>>>3^u<<4^g^l,a+=e[3&h^f]^u,u=o[i]=o[i]+a&-1}return function(r,n){var t=r.length,o=t-1<<2;if(n){var e=r[t-1];if(e<o-3||e>o)return null;o=e}for(var a=0;a<t;a++)r[a]=String.fromCharCode(255&r[a],r[a]>>>8&255,r[a]>>>16&255,r[a]>>>24&255);return n?r.join("").substring(0,o):r.join("")}(o,!1)}'
xencode = js2py.eval_js(xencode_src)

alphabet = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
b64table = str.maketrans(standard, alphabet)


def format_jsonp(jsonp_str):
    return json.loads(jsonp_str[:-1].split("(", 1)[1])


def get_ip_address(ifname):
    if not ifname:
        for _interface in netifaces.interfaces():
            a = netifaces.ifaddresses(_interface).get(netifaces.AF_INET, [{}])[0]
            if a.get("addr", "").startswith("172."):
                return a.get("addr"), _interface
        return "", ""
    else:
        a = netifaces.ifaddresses(ifname).get(netifaces.AF_INET, [{}])[0]
        return a.get("addr"), ifname


def get_challenge(params: dict):
    callback_name = "gugugu"
    params["callback"] = callback_name
    resp = requests.get(BASE_URL + "/cgi-bin/get_challenge", params=params)
    resp_data = format_jsonp(resp.text)

    if resp_data.get("error") != "ok":
        return ""

    return resp_data.get("challenge", "")


def login(username, password, interface, acid):
    current_ip, interface = get_ip_address(interface)
    if not current_ip:
        return "错误：未找到172.*开头的IP"

    token = get_challenge({"username": username, "ip": current_ip})
    if not token:
        return "获取token时出现错误"

    info = "{SRBX1}" + base64.b64encode(
        xencode(
            json.dumps(
                OrderedDict(
                    {
                        "username": username,
                        "password": password,
                        "ip": current_ip,
                        "acid": acid,
                        "enc_ver": "srun_bx1",
                    }
                ),
                sort_keys=False,
                separators=(",", ":"),
            ),
            token,
        ).encode("latin1"),
    ).decode("utf-8").translate(b64table)

    hmd5 = hmac.new(
        bytes(token, "utf-8"), bytes(password, "utf-8"), digestmod="md5"
    ).hexdigest()
    chkstr = token + token.join([username, hmd5, acid, current_ip, "200", "1", info])
    params = {
        "callback": "gugugu",
        "action": "login",
        "username": username,
        "password": "{MD5}" + hmd5,
        "ac_id": acid,
        "ip": current_ip,
        "chksum": hashlib.sha1(bytes(chkstr, "utf-8")).hexdigest(),
        "info": info,
        "n": 200,
        "type": 1,
        "os": "Gugugu OS",
        "name": "Linux",
        "double_stack": 0,
    }

    resp = requests.get(BASE_URL + "/cgi-bin/srun_portal", params=params)
    resp_data = format_jsonp(resp.text)
    if resp_data.get("ecode") == 0:
        renew_ip_address(interface)
        return "登录成功"
    else:
        return resp_data.get("error_msg")


def renew_ip_address(interface):
    if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
        os.system(f"dhclient {interface} -r;dhclient {interface}")
    elif sys.platform.startswith("win32") or sys.platform.startswith("cygwin"):
        os.system(f"ipconfig /release & ipconfig /renew")
    else:
        print("该系统暂不支持，请发issue获取支持：{}".format(sys.platform))


@click.command()
@click.argument("username", type=click.STRING)
@click.argument("password", type=click.STRING)
@click.option(
    "--interface",
    type=click.Choice(netifaces.interfaces()),
    help="获取和更新IPv4的网卡，默认自动寻找IPv4为172.*的网卡",
)
@click.option(
    "--acid", default="11", help="跳转到登录界面时URL中的ac_id，在你使用tjuwlan时为11（默认），使用LAN接入时为7"
)
def main(username, password, interface, acid):
    if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
        euid = os.geteuid()
        if euid != 0:
            print("正在请求root权限以调用dhclient...")
            args = ["sudo", sys.executable] + sys.argv + [os.environ]
            os.execlpe("sudo", *args)

    print(login(username, password, interface, acid))


if __name__ == "__main__":
    main()
