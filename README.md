<div align="center">

# Python-ws
此分支为哪吒v1的python重写版+ws，无二进制。基于python serverless实现的vless+trojan+shadowsocks三协议，轻量，无内核。



---

Telegram交流反馈群组：https://t.me/eooceu

</div>


* 用于python环境的玩具和容器，vless+trojan+shadowsocks三协议，集成哪吒探针服务(v0或v1)，可自行添加环境变量开启

* PaaS 平台设置的环境变量
  | 变量名        | 是否必须 | 默认值 | 备注 |
  | ------------ | ------ | ------ | ------ |
  | UUID         | 否 |5efabea4-f6d4-91fd-b8f0-17e004c89c60| 开启了哪吒v1,请修改UUID|
  | PORT         | 否 |  3000  |  节点监听端口,默认自动获取分配的端口                  |
  | NEZHA_SERVER | 否 |        |哪吒v1填写形式：nz.abc.com:8008   哪吒v0填写形式：nz.abc.com|
  | NEZHA_PORT   | 否 |        | 哪吒v1没有此变量，v0的agent端口| 
  | NEZHA_KEY    | 否 |        | 哪吒v1的NZ_CLIENT_SECRET或v0的agent端口 |
  | NAME         | 否 |        | 节点名称前缀，例如：koyeb |
  | DOMAIN       | 是 |        | 项目分配的域名或已反代的域名，不包括https://前缀  |
  | SUB_PATH     | 否 |  sub   | 订阅token    |
  | AUTO_ACCESS  | 否 |  false | 是否开启自动访问保活,false为关闭,true为开启,需同时填写DOMAIN变量 |
  | DEBUG        | 否 |  false | 调试模式，默认关闭，true开启                   |

* 域名/${SUB_APTH}查看节点信息，非标端口，域名:端口/${SUB_APTH}  SUB_APTH为自行设置的订阅token，未设置默认为sub

    
* 温馨提示：READAME.md为说明文件，请不要上传。
* python混肴地址：https://freecodingtools.org/tools/obfuscator/python

### 使用cloudflare workers 或 snippets 反代域名给节点套cdn加速,也可以使用端口回源方式
```
export default {
    async fetch(request, env) {
        let url = new URL(request.url);
        if (url.pathname.startsWith('/')) {
            var arrStr = [
                'change.your.domain', // 此处单引号里填写你的节点伪装域名
            ];
            url.protocol = 'https:'
            url.hostname = getRandomArray(arrStr)
            let new_request = new Request(url, request);
            return fetch(new_request);
        }
        return env.ASSETS.fetch(request);
    },
};
function getRandomArray(array) {
  const randomIndex = Math.floor(Math.random() * array.length);
  return array[randomIndex];
}
```

# 相关项目
- Nodejs版，连接直达：[node-ws](https://github.com/eooce/node-ws)
- Java 版，链接直达：[java-ws](https://github.com/eooce/java-ws)
- Golang版，连接直达：[golang-ws](https://github.com/eooce/node-ws/tree/golang)

版权所有 ©2025 `eooce`
