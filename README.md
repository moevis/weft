# Weft

通过中继连接远程 TCP 服务，端到端加密。一端发布，另一端绑定到本机即可使用。

## 架构

```text
发布端                         公网中继                       访问端

adbd :5555 --+              +-----------+              +-- :5555 <-- adb
            +-- weft <----> |   weftd   | <----> weft --+
web  :8888 --+              +-----------+              +-- :8080 <-- 浏览器

                 <-------- 端到端加密 -------->
```

两端主动连接中继，无需发布端拥有公网 IP。`weftd` 按 channel 和服务名配对，
只转发密文；访问端将服务绑定到本机端口。一个 channel 可发布多个服务，支持多个客户端独立连接。

## 安装

支持 Linux / macOS，amd64 / arm64。安装到 `~/.local/bin`，无需 sudo。

```sh
curl -fsSL https://raw.githubusercontent.com/moevis/weft/main/scripts/install.sh | bash
```

也可从 [Releases](https://github.com/moevis/weft/releases) 下载安装包。

## 快速开始

**1. 在服务器启动中继**

```sh
weftd -listen :9999
```

**2. 在设备侧发布服务**

```sh
weft -channel phone -endpoint relay.example:9999:/phone-1 \
  -publish adb:5555 -publish web:8888
```

首次运行自动生成密钥并保存配置。后续只需 `weft -channel phone`。

**3. 导出连接配置，私下传给另一端**

```sh
weft -channel phone -export-client -out phone-client.toml
```

**4. 在另一端连接**

```sh
weft -conf phone-client.toml -bind adb:5555 -- adb connect localhost:5555
```

本地端口就绪后执行 `adb connect`，隧道保持运行，按 Ctrl-C 关闭。设备侧需已有可访问的 `adbd` 服务。

## 常用命令

```sh
weft -channel phone -list                  # 查看远端服务
weft -channel phone -bind web:8080         # 远端 web → 本机 8080
weft -channel phone -bind adb \
  -- adb connect '{adb.addr}'              # 自动选择本地端口
weft -h                                   # 所有参数
```

默认读取 `~/.weft.toml`，密钥直接保存在对应 channel 中。用 `-conf` 指定其他文件；只有一个 channel 时可省略 `-channel`。客户端使用导出的配置。

`-publish` 和 `-bind` 可重复指定。本地监听默认仅限 `127.0.0.1`。已有配置的临时参数覆盖不会保存，添加 `-save` 才写回。配置包含密钥，请勿公开。

## 公钥模式

默认使用共享密钥。若要为每个客户端单独授权，在新 channel 上执行：

```sh
weft -channel phone -endpoint relay.example:9999:/phone-1 \
  -mode public -export-client -out phone-client.toml
weft -channel phone -publish adb:5555
```

客户端用法不变。新增客户端后重启发布端；撤销时删除配置中对应的 `allowed_clients` 公钥并重启。
