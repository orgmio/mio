# 编译

本章节介绍如何编译 mio。

## 前提条件

go语言环境，确保装有最新稳定版。

## 编译步骤

1. 克隆项目：

```bash
git clone https://github.com/orgmio/mio.git
cd mio
```

2. 编译：

```bash
go build
```

编译完成后，会生成可执行文件 `mio`。

3. 验证:

```bash
./mio version
```

使用上方命令来验证编译是否成功，如果正常输出版本信息，则表示编译成功。