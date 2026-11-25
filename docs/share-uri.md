# MIO 分享链接规范

`mio://` 链接用于在 MIO 客户端及第三方客户端之间分享单个节点。

## 链接格式

```text
mio://<server>:<server_port>?dest=<dest>&public_key=<public_key>#<name>
```

| 链接部分              | 必填 | 对应配置       | 规则                                                                                         |
| --------------------- | ---- | -------------- | -------------------------------------------------------------------------------------------- |
| 主机                  | 是   | `server`       | ASCII 域名、IPv4 或 IPv6。URI 中的 IPv6 地址须加方括号，解析到配置时去掉方括号。             |
| 端口                  | 是   | `server_port`  | 十进制整数，范围为 1–65535，须显式填写。                                                     |
| `dest` 查询参数       | 是   | `dest`         | 与服务端 `[inbounds].dest` 一致。其值为域名或 IP 地址，IPv6 在值中使用不带方括号的地址。     |
| `public_key` 查询参数 | 是   | `public_key`   | 服务端 `mio keygen` 输出的公钥。采用无填充 base64url，长度为 43 个字符，解码结果为 32 字节。 |
| 片段 `#name`          | 否   | 客户端显示名称 | UTF-8 文本，缺省或为空时由客户端选择默认名称。                                               |

链接的用户信息部分和路径必须为空。国际化域名须以 ASCII 形式写入链接。生成器只写入表中定义的分享字段，服务端私钥和本地 SOCKS5 配置不进入链接。

## 生成和解析

1. 生成器使用小写 `mio` 作为 scheme，并按 `dest`、`public_key` 的顺序输出查询参数。解析器接受任意参数顺序，scheme 按 ASCII 大小写不敏感匹配，参数名按大小写敏感匹配。
2. 生成时，将查询值和节点名转为 UTF-8，再对 URI 非保留字符以外的字节做百分号编码。空格使用 `%20`，加号使用 `%2B`。解析时先按 URI 结构分离各部分，再解码每个查询名、查询值和片段一次。查询中的裸加号按字面加号处理。URI 结构和编码见 [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)。
3. `dest` 和 `public_key` 各须出现一次且值非空。解析器应拒绝缺项、重复必填项、非法端口、非法百分号编码、非法 UTF-8 和格式不合法的公钥。公钥解码后重新编码所得的字符串须与原值一致。解析器必须忽略语法有效的未知查询参数，未来新增的可选参数应保持这一兼容规则。公钥编码见 [RFC 4648 §5](https://www.rfc-editor.org/rfc/rfc4648#section-5)。
4. 导入时将节点名用于界面显示，并将其余字段写入客户端出站。链接的语法校验可在本地完成，连接时再验证服务端可用性和协议兼容性。

## 正例

下面的公钥是文档示例，实际分享时替换为自己服务端生成的公钥。

```text
mio://mio.example.com:443?dest=example.com&public_key=hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo#%E6%88%91%E7%9A%84%E8%8A%82%E7%82%B9
```

转换成mio的toml格式：

```toml
[outbounds]
server = "mio.example.com"
server_port = 443
dest = "example.com"
public_key = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
```

转换成sing-box集成mio的格式：

```json
{
  "type": "mio",
  "tag" : "我的节点",
  "server": "mio.example.com",
  "server_port": 443,
  "dest": "example.com",
  "public_key": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
}
```
