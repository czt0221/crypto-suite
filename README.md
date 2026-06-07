<div align="center">

# Crypto-Suite

[![C](https://img.shields.io/badge/C-gcc_15.2-00599C?logo=c&logoColor=white)](https://gcc.gnu.org/)
[![Pixi](https://img.shields.io/badge/Env-pixi-6D28D9)](https://pixi.prefix.dev/)
[![Build](https://img.shields.io/badge/Build-Makefile-1F2937)](https://www.gnu.org/software/make/)
[![Release](https://img.shields.io/github/v/release/czt0221/crypto-suite)](https://github.com/czt0221/crypto-suite/releases/latest)

[![Download](https://img.shields.io/badge/Download-Latest%20Release-2ea44f?style=for-the-badge)](https://github.com/czt0221/crypto-suite/releases/latest)

</div>

`Crypto-Suite` 是一个使用 C 语言实现的密码算法综合库，涵盖对称加密、哈希、消息认证、编码转换、公钥密码和数字签名共 16 个密码算法模块。所有算法均为纯 C 实现，无外部加密库依赖，支持 Windows / Linux / macOS 三平台。配套的 demo 程序通过 OpenSSL 进行交叉验证，确保正确性。

## 功能概览

- **对称加密**：AES-128（ECB/CBC）、SM4（ECB/CBC）、RC6（ECB/CBC）
- **哈希算法**：SHA-1、SHA-256、SHA3-256、RIPEMD-160
- **消息认证与派生**：HMAC-SHA1、HMAC-SHA256、PBKDF2（SHA1 / SHA256）
- **编码转换**：Base64、UTF-8
- **公钥密码**：RSA-1024bit（密钥生成、加密/解密、PEM 导出）、ECC-160bit（secp160r1 密钥生成、PEM 导出）
- **数字签名**：RSA-SHA1（PKCS#1 v1.5 Type 1）、ECDSA（SHA-1 + secp160r1）
- **基础支撑**：大数运算（bn_t，Montgomery CIOS 模幂、Miller-Rabin 素性检测）、安全随机数（OS API → RDRAND → 确定性回退）

## 技术栈

- `C11 (gcc 15.2)` — 算法实现
- `pixi` — 跨平台环境管理
- `Makefile` — 项目构建
- `OpenSSL 3.6` — demo 交叉验证（可选依赖，仅 demo 使用）

## 快速启动

### 环境要求

- 操作系统：Windows 10+ / Linux / macOS
- 编译器：`gcc`（需 `__int128` 支持，主流 gcc/clang 均已支持）
- 包管理：[`pixi`](https://pixi.prefix.dev/)（>= 0.65.0）

### 安装依赖

```bash
pixi install
```

### 运行方式

构建全部目标：

```bash
pixi run build
```

产物说明：
- `dist/libmycrypto.a` — 静态库
- `dist/crypto` — 命令行工具
- `build/demo` — 综合演示程序

运行命令行工具：

```bash
# 查看所有命令
pixi run crypto

# 示例：计算 SHA-256 哈希
pixi run crypto hash sha256 48656c6c6f
```

运行 16/16 模块演示（含 OpenSSL 交叉验证）：

```bash
pixi run --environment demo demo
```

### 打包环境

构建版本发布：

```bash
# 编译
pixi run build

# 产物位于 dist/ 和 build/ 目录
```

CI 自动发布：推送 `v*` 标签触发 GitHub Actions，三平台构建 → demo 测试 → Release。

## 项目结构

### 仓库文件

```text
crypto-suite/
├── .gitattributes                      # Git 属性配置
├── .gitignore                          # Git 忽略规则
├── .github/workflows/build-release.yml # CI 流水线（三平台构建 + demo 门禁 + Release）
├── pixi.toml                           # pixi 环境、依赖和任务定义
├── pixi.lock                           # pixi 锁文件
├── Makefile                            # 跨平台构建（ifeq Windows_NT 分支）
├── README.md                           # 项目说明文档
├── include/                            # 头文件（所有算法接口声明）
│   ├── crypto.h                        # 主头文件，统一包含所有子模块
│   ├── bignum.h                        # 大数运算
│   ├── rand_util.h                     # 安全随机数
│   ├── aes.h, sm4.h, rc6.h            # 对称加密
│   ├── sha1.h, sha256.h, sha3.h, ripemd160.h  # 哈希
│   ├── hmacsha1.h, hmacsha256.h        # 消息认证
│   ├── pbkdf2.h                        # 密钥派生
│   ├── base64.h, utf8.h               # 编码
│   ├── rsa1024bit.h, ecc160bit.h       # 公钥密码
│   └── rsasha1.h, ecdsa.h             # 数字签名
├── src/                                # 实现文件
│   ├── bignum.c                        # 大数运算：四则运算、Montgomery 模幂、扩展欧几里得模逆、Miller-Rabin
│   ├── rand_util.c                     # 随机数链：OS API → RDRAND → srand/rand 回退
│   ├── aes.c, sm4.c, rc6.c            # 对称加密
│   ├── sha1.c, sha256.c, sha3.c, ripemd160.c  # 哈希
│   ├── hmacsha1.c, hmacsha256.c        # HMAC
│   ├── pbkdf2.c                        # PBKDF2（通用实现，支持 SHA1/SHA256）
│   ├── base64.c, utf8.c               # 编码
│   ├── rsa1024bit.c, ecc160bit.c       # 公钥密码 + PEM 导出
│   ├── rsasha1.c, ecdsa.c             # 数字签名
│   └── crypto.c                        # CLI 入口
└── demo/                               # 演示程序
    └── demo.c                          # 16 模块综合演示 + OpenSSL 交叉验证
```

### 运行后生成的文件

```text
build/                                  # 编译中间文件
├── *.o                                 # 目标文件
├── *.d                                 # 依赖文件
└── demo                                # 演示程序

dist/                                   # 发布产物
├── libmycrypto.a                       # 静态链接库
└── crypto                              # 命令行工具
```

## 安全性警告

> **本项目仅用于学习与教学用途。** 代码以实现算法功能为主，未经过安全审计，**可能存在多处安全漏洞**（如侧信道攻击、时序攻击、内存安全等），**禁止用于生产环境或任何需要密码学保密的实际场景**。需要可靠密码学实现的场所，请使用 OpenSSL、libsodium 等经过专业审计的加密库。
