# opencl_vanity_gpg

使用 GPU（OpenCL）快速生成带有“靓号”的 PGP 密钥！

“靓号”指的是带有连号等特定格式的密钥指纹或 ID（例如以 `77777777` 结尾），具体介绍和生成原理请参见：

- [一位 PGP 进步青年的科学算号实践](https://www.douban.com/note/763978955/)
- [某科学的 PGP 算号指南](https://blog.dejavu.moe/posts/the-scientific-vanity-pgp-counting-guide/)

![](https://github.com/user-attachments/assets/e6364d93-fffe-4fcd-9857-b70155e6f476)

简单来说，密钥指纹是密钥生效时间和公钥内容的 SHA-1，通过不断生成密钥和修改时间（成本更低）的暴力遍历方式找到“靓号”。

> [!TIP]
>
> 姊妹项目：使用 WebGL 实现的网页版 [TransparentLC/webgl-vanity-gpg](https://github.com/TransparentLC/webgl-vanity-gpg)
>
> 实际上这个项目也可以当成是它的“锈化”版…\_φ(･ω･` )

目前最好的同类工具是使用 CPU 的 [RedL0tus/VanityGPG](https://github.com/RedL0tus/VanityGPG) 和使用 GPU（CUDA）的 [cuihaoleo/gpg-fingerprint-filter-gpu](https://github.com/cuihaoleo/gpg-fingerprint-filter-gpu)。这个项目是使用 GPU（OpenCL）实现的，优点当然是开箱即用了。

GitHub Actions 有自动编译好的二进制文件。

> [!NOTE]
>
> 如果你生成了指纹以 `00000000` 结尾的私钥，由于 GnuPG 的一个 bug，它们将无法正常显示信任等级，但是仍然可以使用。相关讨论见 [Issue #5](https://github.com/TransparentLC/opencl_vanity_gpg/issues/5)。

# 使用方法

```console
$ opencl_vanity_gpg -h
Usage: opencl_vanity_gpg [OPTIONS]

Options:
  -c, --cipher-suite <CIPHER_SUITE>
          Cipher suite of the vanity key
          ed25519, ecdsa-****, rsa****       => Primary key
          cv25519,  ecdh-****                => Subkey
          ed25519-sign, ecdsa-****-sign      => Signing subkey
          Use gpg CLI for further editing of the key. [default: ed25519] [possible values: ed25519, cv25519, rsa2048, rsa3072, rsa4096, ecdh-p256, ecdh-p384, ecdh-p521, ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519-sign, ecdsa-p256-sign, ecdsa-p384-sign, ecdsa-p521-sign]
  -u, --user-id <USER_ID>
          OpenPGP compatible user ID [default: "Dummy <dummy@example.com>"]
  -p, --pattern <PATTERN>
          A pattern less than 40 chars for matching fingerprints
          Can be given multiple times (or comma-separated).
          > Format:
          * 0-9A-F are fixed
          * G-Z are wildcards, the same letter must be the same digit (e.g. GGGG)
          * '#' matches a decimal digit (0-9), '*' or '?' match anything
          * '!' negates what follows (e.g. !7 is not 7, G!G means two different digits)
          * '^' anchors at the start of the fingerprint, the default (or '$') at the end
          * Other chars will be ignored, case insensitive
          > Target:
          * Prefix a pattern with primary:, sign:, encrypt: or all: (combine with '+')
            to match it against those key packets only
          * Without a prefix, the packets given by --algorithm are used
          > Example:
          * 11XXXX** may output a fingerprint ends with 11222234 or 11AAAABF
          * 11XXYYZZ may output a fingerprint ends with 11223344 or 11AABBCC
          * ^ABCD starts with ABCD
          * sign:#### makes the signing subkey end with 4 decimal digits
  -a, --algorithm <ALGORITHM>
          Key packet(s) the patterns are matched against
          primary, encrypt, sign, or all. Can be given multiple times
          (or comma-separated, or joined with '+').
          Defaults to the packet selected by --cipher-suite.
  -f, --filter <FILTER>
          OpenCL kernel function for uint h[5] for matching fingerprints
          Ignore the pattern and no estimate is given if this has been set
          > Example:
          * (h[4] & 0xFFFF)     == 0x1234     outputs a fingerprint ends with 1234
          * (h[0] & 0xFFFF0000) == 0xABCD0000 outputs a fingerprint starts with ABCD
  -o, --output <OUTPUT>
          The dir where the vanity keys are saved
  -d, --device <DEVICE>
          Device ID to use
  -t, --thread <THREAD>
          Adjust it to maximum your device's usage
  -i, --iteration <ITERATION>
          Adjust it to maximum your device's usage [default: 512]
      --timeout <TIMEOUT>
          Exit after a specified time in seconds
      --oneshot
          Exit after getting a vanity key (any pattern matching once)
      --shot-all
          Keep searching until every pattern has matched at least once
      --no-progress
          Don't print progress
      --no-secret-key-logging
          Don't print armored secret key
      --list-device
          Show available OpenCL devices then exit
      --future-timestamp
          Generate keys with future timestamps instead of past timestamps
          When true: search from start_timestamp forward in time (start_timestamp + 0 to max_time_range)
          When false: search from start_timestamp backward in time (start_timestamp - max_time_range to start_timestamp - 0)
      --start-timestamp <START_TIMESTAMP>
          Custom timestamp to start searching from (Unix timestamp)
          This is the base time point from which the search begins
          If not specified, uses current time as the starting point
          Example: 1640995200 (Jan 1, 2022 00:00:00 UTC)
      --max-time-range <MAX_TIME_RANGE>
          Maximum time range to search in seconds
          future_timestamp =  true: search from start_timestamp to (start_timestamp + max_time_range)
          future_timestamp = false: search from (start_timestamp - max_time_range) to start_timestamp
      --key-file <PATH>
          Add a vanity subkey to this existing secret key instead of generating a new one
          Accepts an exported secret key (ASCII-armored or binary), for example:
          `gpg --export-secret-keys --armor <KEY-ID> > key.asc`
          --cipher-suite selects the subkey type: cv25519 / ecdh-* add an
          encryption subkey, ed25519-sign / ecdsa-*-sign add a signing subkey
          The primary key and its existing subkeys are kept as they are
      --key-id <KEY_ID>
          Select a key by fingerprint or key ID when --key-file contains several keys
      --passphrase <PASSPHRASE>
          Passphrase of the key given by --key-file, if it is protected
      --passphrase-file <PATH>
          Read the passphrase of --key-file from the first line of a file
      --cpu
          Search on the CPU instead of the GPU
          No OpenCL device is opened or used. The binary still links against the
          OpenCL runtime unless it was built with --no-default-features.
          Combine with --gpu to search on both at the same time.
      --gpu
          Use the GPU (the default)
          Combine with --cpu to search on the GPU and the CPU at the same time.
      --cpu-threads <N>
          Number of CPU threads to use with --cpu [default: logical CPUs]
  -h, --help
          Print help
  -V, --version
          Print version

$ opencl_vanity_gpg -p 11XXYYZZ --oneshot
[2025-01-08T19:00:25Z INFO  opencl_vanity_gpg] Using device: Apple M1 Pro
[2025-01-08T19:00:25Z INFO  opencl_vanity_gpg] Auto set thread: 1048576
[2025-01-08T19:00:25Z INFO  opencl_vanity_gpg] You will get vanity keys created after 2008-01-05T00:11:53.021Z
[2025-01-08T19:00:25Z WARN  opencl_vanity_gpg] No output dir given. Generated vanity keys will not be saved.
[2025-01-08T19:00:26Z INFO  opencl_vanity_gpg::utils::vanity_key] Get a vanity key:
-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgER4EupBYJKwYBBAHaRw8BAQdAI4vIy0CaErtwj1iAQInMQYwIz4BMo30MfS1s
Kg0FYMUAAP4oOaeAXKE3fHhq1H28qYI+j7awA2iYQW7+fgTODpyXWxAfzRlEdW1t
eSA8ZHVtbXlAZXhhbXBsZS5jb20+wo4EEBYIADYCGQEFAmd+y0oCGwMECwkIBwUV
CgkICwUWAgMBAAEnFiEEucj6sO6iKUnbGDpx5F4DcRHMZiIACgkQ5F4DcRHMZiJ0
iQD/cUPO7lBsDbg5wyFwXalTvzcac8865OakjsdmA+bJPc8A/insYTxgzA/boh7i
ieogUSu64E0VyYGnfjcnIMX33mQPx10ER4EupBIKKwYBBAGXVQEFAQEHQPHXTpFg
T6dZ/eudJ0W+JzzfuzK8cCWlDcaWD/DEogVRAwEIBwAA/2I4tvG84tjPcZGxClnJ
nUpTRDrLvKtelZ5QBZLJbNJoEjXCeAQYFggAIAUCZ37LSgIbDBYhBLnI+rDuoilJ
2xg6ceReA3ERzGYiAAoJEOReA3ERzGYi8QwBAPr0n0eGhbNt5PMUfDccx4ttthFm
xsCkD3wdoVaA7t/BAQCvPyuVmtJN4M8gsYNRZYEfLwb1BIckohZv+svENGSqAw==
=ZeYm
-----END PGP PRIVATE KEY BLOCK-----

[2025-01-08T19:00:26Z INFO  opencl_vanity_gpg::utils::vanity_key] Created at: 2008-01-06T19:40:20.000Z (1199648420)
[2025-01-08T19:00:26Z INFO  opencl_vanity_gpg::utils::vanity_key] Fingerprint #0: B9C8FAB0EEA22949DB183A71E45E037111CC6622
[2025-01-08T19:00:26Z INFO  opencl_vanity_gpg::utils::vanity_key] Fingerprint #1: 7FBC6D063D9C4CF4C281E8A14876C8831552E9B4
[2025-01-08T19:00:26Z INFO  opencl_vanity_gpg] Hashed: 536.87M (512.00x) Time: 1.53s Speed: 351.76M hash/s
```

一个 Curve25519 的密钥由用来签名和认证的 Ed25519 主密钥和用来加密的 Cv25519 子密钥组成。VanityGPG [只能生成主密钥为“靓号”的密钥](https://github.com/RedL0tus/VanityGPG/issues/5)，而这个项目也可以生成子密钥为“靓号”的密钥（只需要添加参数 `-c cv25519` 即可）。对于其他 NISP P-\*\*\* 的椭圆曲线的密钥也是类似的。

如果需要为**签名子密钥**计算靓号（常用于把只负责认证的主密钥离线保存、日常使用签名子密钥的场景），可以使用 `-c ed25519-sign` 或 `-c ecdsa-p256-sign` / `ecdsa-p384-sign` / `ecdsa-p521-sign`。这样生成的密钥结构为：

- 主密钥：只具备认证（certify）能力；
- 签名子密钥：具备签名能力，靓号计算的就是它的指纹；
- 加密子密钥：具备加密能力。

签名子密钥的绑定签名中会嵌入由子密钥自身生成的交叉认证签名（cross-certification / primary key binding signature），因此 GnuPG 不会将其视为“未交叉认证”的签名子密钥。

## 同时匹配多个 pattern

`-p/--pattern` 可以重复指定（也可以用逗号分隔）：

```console
# 主密钥指纹以 1111 或 2222 结尾就退出
$ opencl_vanity_gpg -p 1111 -p 2222 --oneshot

# 所有 pattern 都至少命中一次后才退出，每命中一个就保存一个密钥
$ opencl_vanity_gpg -p 1111 -p 2222 -o vanity-keys --shot-all
```

- `--oneshot`：任意一个 pattern 命中即退出；
- `--shot-all`：所有 pattern 都至少命中一次后才退出（每次命中都会输出/保存一个密钥，直到全部满足）；
- 两者都不指定：持续搜索，每次命中都会输出/保存一个密钥。

## 同时对多种密钥包计算

`-a/--algorithm` 用于指定 pattern 要匹配哪些密钥包，可以重复指定（或用逗号、`+` 分隔），取值为 `primary`（主密钥）、`encrypt`（加密子密钥）、`sign`（签名子密钥）或 `all`（全部）。不指定时沿用 `-c` 对应的默认密钥包。

```console
# 主密钥或签名子密钥的指纹以 AAAA 结尾即可
$ opencl_vanity_gpg -c ed25519-sign -a primary,sign -p AAAA --oneshot

# 主密钥、签名子密钥、加密子密钥同时计算
$ opencl_vanity_gpg -c ed25519-sign -a all -p XXYY --oneshot

# 也可以用 pattern 的前缀单独指定目标（优先于 -a）
$ opencl_vanity_gpg -c ed25519-sign -p primary:AAAA -p sign:BBBB --shot-all
```

同时计算 N 个密钥包时，每个候选时间戳都要做 N 次 SHA-1，因此每秒处理的候选数量约为单目标时的 1/N（输出的 hash/s 仍然按实际 SHA-1 次数统计）。

## Pattern 语法

| 写法 | 含义 |
| - | - |
| `0-9`、`A-F` | 固定字符 |
| `G-Z` | 通配符，相同的字母必须对应相同的数字：`GGGG` 表示末 4 位相同 |
| `#` | 十进制数字（0-9） |
| `*`、`?` | 任意字符 |
| `!` | 否定后面的一个字符：`!7` 表示不是 7，`G!G` 表示两位不相同 |
| `^`、`$` | 锚定指纹开头 / 结尾（默认对齐结尾） |

例如：

- `77777777`：以 8 个 7 结尾；
- `GGGG`：末 4 位相同（`1234` 不算）；
- `^ABCD`：以 ABCD 开头；
- `##!A`：末 3 位依次是十进制数字、十进制数字、且不是 A；
- `sign:####`：签名子密钥末 4 位都是十进制数字。

# 在已有密钥上追加靓号子密钥

除了从零生成整把密钥，还可以为**已经存在**的密钥追加一个靓号子密钥：主密钥和原有的子密钥完全保持不变（指纹、自签名都不变），只有新子密钥的指纹交给 GPU 计算。

先导出已有的私钥（建议先备份）：

```console
$ gpg --export-secret-keys --armor <KEY-ID> > mykey.asc
```

然后指定 `--key-file`，并用 `-c` 选择要追加的子密钥类型：

```console
# 追加加密子密钥（指纹以 77777777 结尾）
$ opencl_vanity_gpg --key-file mykey.asc -c cv25519 -p 77777777 --oneshot -o vanity-keys

# 追加签名子密钥（指纹末 4 位是十进制数字）
$ opencl_vanity_gpg --key-file mykey.asc -c ed25519-sign -p sign:#### --oneshot -o vanity-keys

# 密钥有口令保护时
$ opencl_vanity_gpg --key-file mykey.asc --passphrase '……' -c cv25519 -p 77777777 --oneshot

# 口令从文件读取（取第一行）；文件里有多把密钥时用 --key-id 选择
$ opencl_vanity_gpg --key-file keyring.gpg --key-id 0x12345678 --passphrase-file pass.txt -c cv25519 -p ABCD
```

输出的文件是包含新子密钥的**完整私钥**（命名为 `<主密钥指纹>-<新子密钥指纹>-sec.asc`），直接用 `gpg --import` 导入即可：

```console
$ gpg --import vanity-keys/*.asc
```

需要注意：

- `-c` 必须指定子密钥类型：`cv25519`、`ecdh-p256`、`ecdh-p384`、`ecdh-p521` 追加加密子密钥；`ed25519-sign`、`ecdsa-p256-sign`、`ecdsa-p384-sign`、`ecdsa-p521-sign` 追加签名子密钥（会同时生成交叉认证签名）。其他取值会报错。
- 只支持 v4 密钥（v6 密钥使用 SHA-256 指纹，而 GPU 内核只实现了 SHA-1）。
- 只有新子密钥参与匹配：`-a primary`、`primary:` 前缀等都会报错，因为导入的密钥包不会重新生成。
- 新子密钥的创建时间不会早于主密钥的创建时间（GnuPG 拒绝生成这种密钥）。所以对**刚刚创建**的密钥没有“过去”可以搜索，程序会自动改为向未来搜索并打印提示；也可以用 `--start-timestamp`、`--future-timestamp`、`--max-time-range` 自行控制。
- 当可搜索的时间窗口很短（主密钥很新）时，程序会自动在一次 GPU 启动中并行搜索多份候选子密钥（日志会提示 `N candidate subkeys are searched per GPU round`），避免每轮只计算少量哈希而拖慢速度。
- 新子密钥继承导入密钥的口令保护：搜索过程中候选密钥不加密，命中后才用同一口令加密。
- 原有子密钥会保留。GnuPG 加密时一般使用最新的加密子密钥；如果只想使用新子密钥，可以用 `gpg --edit-key` 撤销旧的或给它设置过期时间。
- 重新导入后如果旧子密钥仍在，它们依然可用，行为与普通的“多子密钥”密钥相同。

# 使用 CPU 计算

默认只使用 GPU。需要时可以用 `--cpu` 只用 CPU，或用 `--cpu --gpu` 让两者同时搜索：

```console
# 只用 CPU（12 线程）
$ opencl_vanity_gpg --cpu --cpu-threads 12 -c ed25519 -p 77777777 --oneshot

# GPU 和 CPU 同时搜索
$ opencl_vanity_gpg --cpu --gpu -c ed25519 -p 77777777 --oneshot

# 在已有密钥上追加靓号子密钥同样适用
$ opencl_vanity_gpg --cpu --gpu --key-file mykey.asc -c cv25519 -p 77777777 --oneshot
```

- `--cpu` 只用 CPU，不会初始化 GPU，也不会打开任何 OpenCL 设备（但程序仍然在链接期依赖 OpenCL 运行库，除非用 `--no-default-features` 构建）。
- `--gpu` 就是不写参数时的默认行为。`--cpu --gpu` 时，每轮的时间戳窗口按两者实测速度分给 GPU 和 CPU 并行搜索：CPU 通常分担约 1%–2%，两边搜索不同的时间戳，任意一方先命中就采用谁的结果。CPU 的份额会随每轮实测的 GPU 速度自动调整，并预留一个逻辑 CPU 给 OpenCL 驱动线程，因此不会拖慢 GPU；受算力比例限制，整体提升在 1%–2%。窗口太小时 CPU 会自动不参与该轮。
- `--cpu` 模式下 `--thread`、`--iteration`、`--device` 都不再生效，线程数用 `--cpu-threads`（默认为逻辑 CPU 数；混合模式下会少用一个）。
- 只支持 `--pattern`：`--filter` 是 OpenCL 表达式，纯 CPU 模式会直接报错；混合模式下 CPU 会自动退出，只用 GPU。
- CPU 后端使用 RustCrypto 的 SHA-1 实现：CPU 支持 SHA 扩展（Intel Ice Lake / AMD Zen 及更新的型号）时自动走 SHA-NI 硬件指令，12 线程实测约 150M hash/s；不支持时回退到可移植实现（约 40–50M hash/s）。比 GPU 仍慢一到两个数量级，适合没有 GPU 的机器、较短的 pattern，或者作为 GPU 的少量补充。

## 只构建 CPU 版本

默认构建包含 GPU（OpenCL）后端，因此程序在启动时依赖 OpenCL 运行库（Windows 上是 `OpenCL.dll`）。如果目标机器根本没有 OpenCL，可以用 `--no-default-features` 编译一个完全不链接 OpenCL 的 CPU 版本：

```console
$ cargo build --release --no-default-features
```

这样的程序没有 GPU 后端，总是使用 CPU（`--list-device` 会报错说明不支持），构建时也不再需要 `OpenCL.lib`。不加这个参数时默认包含 GPU 支持。

# 性能对比

| Repo | 计算方式 | 速度（hash/s） | 注释 |
| - | - | - | - |
| [RedL0tus/VanityGPG](https://github.com/RedL0tus/VanityGPG) | CPU | 165m | Xeon w5-2465X ×16 cores <br> Arch Linux |
| 这个项目 | CPU | 120m | Xeon w5-2465X ×16 cores <br> Arch Linux <br> CPU 也可以是 OpenCL 的计算设备，虽然性能损耗比较严重…… |
| [cuihaoleo/gpg-fingerprint-filter-gpu](https://github.com/cuihaoleo/gpg-fingerprint-filter-gpu) | GPU | 1b | A16 1/8 <br> Ubuntu 24.04 |
| 这个项目 | GPU | 1.5b | A16 1/8 <br> Ubuntu 24.04 |
| [TransparentLC/webgl-vanity-gpg](https://github.com/TransparentLC/webgl-vanity-gpg) | GPU | 2b | GTX 1070 <br> Windows 11 |
| 这个项目 | GPU | 3b | GTX 1070 <br> Windows 11 |
| [TransparentLC/webgl-vanity-gpg](https://github.com/TransparentLC/webgl-vanity-gpg) | GPU | 7b | RTX A5500 <br> Windows 11 |
| 这个项目 | GPU | 12b | RTX A5500 <br> Windows 11 |
| 这个项目 | GPU | 32b | RTX 4090 <br> Ubuntu 22.04 |
| 这个项目 | GPU | 240m | RTX 4090 <br> Ubuntu 22.04 rsa4096 |
| 这个项目 | GPU | 42b | RTX 5090 <br> Windows 11 |
| 这个项目 | GPU | 380m | Apple M1 Pro |
| 这个项目 | GPU | 1.6b | Apple M4 Pro |

除另有标注外，以上的速度均为生成 cv25519 类型的密钥的速度。
