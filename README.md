# tju-srun-login

通过命令行登录天津大学校园网

因为实验室网络结构原因，无法使用PPPoE拨号来连接天津大学校园网，只能通过网页认证登录+release/renew IPv4地址来使用校园网。于是，这个小工具就应运而生了

其实在校园网计费系统更新前，有一个更简单的shell脚本用于登录校园网，然而系统更新后整个认证逻辑就变得复杂了许多，就写成了Python脚本

## 使用说明
```bash
# git clone https://github.com/tongyifan/tju-srun-login
# cd tju-srun-login
# virtualenv venv
# source venv/bin/activate (venv\Scripts\activate in Windows)
(venv) # pip install -r requirements.txt
(venv) # python login.py --help
```

## 主要逻辑
0. `python login.py --acid 7 username password interface`
1. token = 通过向 `/cgi-bin/get_challenge` 传入用户名和指定网卡的当前IP -> **token**
2. info = 通过js2py调用xEncode函数，传入username, password, ip, acid和enc_ver -> **info**
3. hmd5 = hmac md5编码password（key为token）
4. chkstr = `token + token.join([username, hmd5, acid, current_ip, "200", "1", info])`
5. 构造请求 `/cgi-bin/srun_portal`
6. 通过返回值判断是否登录成功，如果登录成功则更新指定网卡的IPv4地址（目前只测试了Manjaro Linux和Windows）

## 其他
* Linux下调用 `dhclient` 需要root权限，所以如果不使用root启动的话会自动使用sudo请求授权
