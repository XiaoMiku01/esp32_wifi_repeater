# ESP32 Wi-Fi 中继

基于 ESP32-S3 的 Wi-Fi 中继：STA 连接上游路由器，SoftAP 给下游设备上网（NAPT），
附带网页配置、DNS 中继与自定义解析，以及一个同时支持 HTTP/2 和 HTTP/1.1 的 HTTPS 站点。

> 配置页没有登录，也不加密传输；Wi-Fi 密码与上传的私钥以明文存放在 Flash 中。
> 只建议在自己可控的网络中使用。

## 功能

- **Wi-Fi 中继**：APSTA 模式 + lwIP NAPT；上游断线自动重连
- **网页配置**（`http://192.168.4.1/`）
  - 上游 Wi-Fi：扫描附近网络（按信号强度排序）后点选
  - 本机热点：SSID、密码、最大客户端数；保存到 NVS，无需重启即生效
  - 运行状态与实时日志（WebSocket，连接时补发历史）
- **DNS 中继**：监听 `192.168.4.1:53`，转发到上游 DNS（客户端何时连入都能解析）
- **DNS 自定义解析**：最多 16 个域名，A 记录返回指定 IPv4（留空为 AP 地址），
  AAAA 等其他类型回空应答；未配置的域名转发上游
- **HTTPS 站点（端口 443）**
  - 自研组件 `components/h2_server`：esp-tls 服务端 + ALPN + [nghttp2](https://github.com/nghttp2/nghttp2)
  - 同时支持 HTTP/2 与 HTTP/1.1（持久连接、流水线）
  - 域名、证书链、私钥可在网页上修改，热替换，新连接生效
  - 客户端证书（mTLS）默认忽略
- **HTTP/2 自定义接口**：最多 8 条「路径 → JSON」
  - 匹配不区分方法与大小写，忽略结尾斜杠和查询串；路径在请求路径中任意位置整段出现即命中
    （设置 `/abc` 时 `/abc`、`/a/abc`、`/abc/x` 都命中），多条命中取最长
  - 应答：`Content-Type: application/json`、`X-Checksum: <md5(body)>`、`Cache-Control: no-store`，
    正文为压缩 JSON
  - 命中时实时日志高亮并弹出提示
- **配置备份**：导出 / 导入 YAML（Wi-Fi、DNS 自定义解析、HTTPS 站点、自定义接口）

## 硬件

开发与测试使用的板子：

| 项目 | 值 |
|---|---|
| 芯片 | ESP32-S3，240 MHz 双核 |
| Flash | 8 MB，**DIO** 模式 |
| PSRAM | 2 MB，quad 模式 |

其他 ESP32-S3 板子需要按实际情况修改 `sdkconfig.defaults` 中的 Flash / PSRAM 配置。
若 Flash 支持 QIO，可改用 `CONFIG_ESPTOOLPY_FLASHMODE_QIO`。

## 构建与烧录

需要 ESP-IDF v6.1.x。

1. 准备 HTTPS 站点证书（不入库，构建时嵌入固件；缺失时构建会报错）：

   ```
   main/certs2/www.aabbcc.com.fullchain.pem   # 证书链（PEM，含中间证书）
   main/certs2/www.aabbcc.com.key             # 私钥（PEM，未加密）
   ```

   只是试用的话可以生成一张自签证书（浏览器会提示不受信任）：

   ```bash
   mkdir -p main/certs2
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
     -subj "/CN=www.aabbcc.com" -addext "subjectAltName=DNS:www.aabbcc.com" \
     -keyout main/certs2/www.aabbcc.com.key -out main/certs2/www.aabbcc.com.fullchain.pem
   ```

   默认域名在 `main/repeater.h` 的 `H2_SITE_DEFAULT_DOMAIN`；烧录后也可在网页上换成自己的域名和证书。

2. 编译并烧录：

   ```bash
   idf.py set-target esp32s3
   idf.py -p <串口> flash monitor
   ```

   首次构建会通过组件管理器下载 `espressif/nghttp`（版本见 `dependencies.lock`）。

## 使用

1. 连接热点 `ESP32-Repeater`，默认密码 `12345678`（`sdkconfig.defaults` 中修改默认值）
2. 打开 `http://192.168.4.1/`，扫描并选择上游 Wi-Fi，填写密码后保存
3. 连上上游后，热点下的设备即可上网

恢复出厂默认值：`idf.py -p <串口> erase-flash` 后重新烧录。

### HTTPS 站点内置接口

DNS 中继默认把 `www.aabbcc.com` 解析到 `192.168.4.1`，连接热点后可直接访问：

| 路径 | 说明 |
|---|---|
| `/` | 说明页 |
| `/ping` | 协议（h2 / http/1.1）、流编号、客户端地址 |
| `/status` | 中继运行状态 |
| `/headers` | 回显请求头 |
| `/echo` | 原样回显请求体 |

```bash
curl --http2 https://www.aabbcc.com/ping
```

### 配置页 API（端口 80）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 运行状态 |
| GET / POST | `/api/config` | Wi-Fi 配置（GET 不返回密码） |
| GET | `/api/scan` | 扫描周边网络 |
| GET | `/api/log` | 历史日志（纯文本） |
| POST | `/api/restart` | 重启 |
| GET / POST | `/api/h2routes` | 自定义接口（`action=set&path=&json=` / `action=del&path=`） |
| GET / POST | `/api/dns` | DNS 自定义解析（`action=set&name=&ip=` / `action=del&name=`） |
| GET / POST | `/api/h2site` | HTTPS 站点（`action=set&domain=&cert=&key=` / `action=reset`），GET 不返回私钥 |
| GET | `/api/export` | 导出全部配置 JSON（含密码与私钥） |
| GET | `/ws` | 实时日志 WebSocket |

POST 均为 `application/x-www-form-urlencoded`。

## 目录结构

```
components/h2_server/   HTTP/2 + HTTP/1.1 服务端组件（esp-tls + nghttp2）
main/
  wifi_repeater.c       Wi-Fi APSTA、NAPT、启动流程
  repeater_config.c     Wi-Fi 配置（NVS）
  dns_relay.c           DNS 中继与自定义解析
  web_server.c          配置页 HTTP 服务与 API
  web_log.c             日志转发到 WebSocket
  h2_test.c             HTTPS 站点的路由与内置接口
  h2_routes.c           自定义接口（NVS）
  h2_site.c             站点域名与证书（NVS，热替换）
  www/index.html        配置页
```

## 已知限制

- 配置页与 API 没有认证，热点与上游局域网内的设备都能访问和修改
- DNS 自定义解析只对使用 `192.168.4.1` 作为 DNS 的设备有效；
  开启私人 DNS / 安全 DNS（DoH、DoT）的设备会绕过
- 原生 USB 口在烧录后用串口工具读取时偶尔失去响应，需要重新插拔
