# cryptoexp

**面向 CTF、安全评估与研究的密码学工具库** —— pwntools 风格的零依赖原语工具箱，外加一层分析管线。

**作者：coolmoon & guaidao2** —— MIT。import 名与 PyPI 发行名都是 `cryptoexp`
（原定的 `cryptokit` 已被 2022 年的另一个不相关项目占用，所以改用这个名字）。

[English README](https://github.com/guaidao2/cryptoexp/blob/main/README.md) ·
[仓库地址](https://github.com/guaidao2/cryptoexp)

- 库用法：`import cryptoexp as cx` —— 数论与模运算、多项式与 GF(2) 代数、编码与古典密码、
  分组与流密码、哈希长度扩展、PRNG 状态恢复、RSA 与签名攻击、格工具、oracle 攻击，
  以及面向真实材料的取证/评估层（批量密钥共享素因子、DER 签名与 JWT 解析、弱 PRNG 指纹）。
- 命令行：`python3 cryptoexp_cli.py analyze|hypotheses|lab|list`（分析管线、JSON 契约、生成解题脚本）。
- **零依赖**：核心只用标准库（AES、LLL、Coppersmith、SHA-1/2 长度扩展、ChaCha20、MT19937
  都是自己实现的）。可选加速库（`gmpy2`、`sympy`、`pycryptodome`、`z3`）自动探测，缺失也不影响正确性。
- **源码与工具输出英文优先**（报告、生成的脚本、docstring 都是英文）；本文档是中文说明。
- CTF 解题是核心目标，**但不是唯一目标** —— 见 [不止 CTF](#不止-ctf安全评估与密码学研究)。
- 不做 Web 界面：这是一个库加一个命令行工具。

---

## 自定义 flag 格式（库优先）

"flag 长什么样" 是具体场景的属性，不是库的属性，所以它可以在三个层面配置，
全部在 `pip install cryptoexp` 之后就能直接用：

```python
from cryptoexp import flag_candidates, find_flags, set_flag_prefixes

# 1) 每次调用显式指定（无隐藏状态 —— 写库、写服务时的正确做法）
flag_candidates(payload, prefixes=["DH", "corp_"])     # 匹配 DH{...}、corp_...{...}
flag_candidates(payload, pattern=r"ACME-\d{4}-[a-z0-9]{8}")   # 任意格式

# 2) 进程级默认（脚本、notebook）
set_flag_prefixes(["DH"], merge=True)
flag_candidates(payload)                              # 此时用 DH 加内置前缀表

# 3) 环境变量（命令行、CI）
#   CRYPTOEXP_FLAG_PREFIXES=DH,corp_ cryptoexp analyze challenge.txt
```

命令行同样支持：`--flag-prefix DH`（可重复）与 `--flag-regex '<正则>'`。

`find_flags(data, prefixes=[...])` 是通用入口：它返回每一段形似标记的字符串，
附带 `{"match", "kind": "strict"|"loose", "offset"}`。这个函数适合用在内存镜像、
配置文件、日志这类真实材料上，而不是只用在题目描述里。前缀按字面量匹配
（含 `.` 的前缀不会误配 `abc{...}`）、大小写不敏感，而题面里 `DH{...}` 这种占位写法
**刻意不算 flag** —— 否则题目会自己把自己"确认"掉。

`analyze_all(path, flag_prefixes=["DH"])` 把格式限定在那一次调用内
（用 `ContextVar` 实现，并发调用之间不会串味），并把它记进结果里，
所以验证与 JSON 报告和调用方保持一致。

---

## 不止 CTF：安全评估与密码学研究

同一批原语也回答真实工作中的问题。库优先，全部可从包根取到：

| 问题 | 调用 |
|---|---|
| 我们这批公钥里有没有共享素因子的？ | `batch_gcd(moduli)` → 返回成对索引与因子分组，基于乘积树，支持上千把密钥 |
| 这把 RSA 密钥弱不弱？ | `audit_rsa_key(n, e, extra_moduli=[...])` → 带等级的发现（`fermat_close_primes`、`wiener_vulnerable`、`shared_factor`、`small_exponent` 等） |
| 这个 token 真的是随机的吗？ | `detect_weak_prng(outputs)` → 识别 LCG / glibc `rand` / xorshift / Java `Random` / MT19937，且只在恢复结果能重放观测值时才下结论 |
| 这段抓包里是什么？ | `parse_jwt(token)`、`parse_der_signature(der)`、`parse_pem`/`parse_ssh_public_key`、`key_fingerprint_sha256` |
| 这份 dump 里哪些地方像标记串？ | `find_flags(data, prefixes=[...])` |
| 两条签名用同一个随机数？ | `ecdsa_nonce_reuse(...)` / `dsa_nonce_reuse(...)` → 直接还原私钥 |
| 这个校验和能伪造吗？ | `crc_forge_append(...)`、`crc_solve_unknown(...)` |
| 这个 MAC 能长度扩展吗？ | `length_extension(...)`、`HashState` |

边界如实说明（在这一块夸大比缺功能更糟）：cryptoexp **不做**网络 IO、不扫描、不解析
HTTP/TLS 会话。oracle 类攻击需要你提供一个回调（针对目标写十行适配层即可），
分析管线预期输入是"一段题面 + 密文块"。对研究用途，它提供的是可组合的原语
（LLL、Coppersmith、GF(2)/GF(p) 代数、离散对数、PRNG 状态恢复、CRC/JWT/DER 处理），
并配有官方向量测试。

---

## 安装

```bash
pip install cryptoexp          # 等有稳定版之后（见下面的 alpha 说明）
pipx install cryptoexp         # 只要命令行工具的话
```

目前所有版本都是**预发布版**（`0.1.0aN`），所以 pip 需要加 `--pre`：

```bash
pip install --pre cryptoexp
```

从克隆的仓库直接跑则什么都不用装：

```bash
git clone https://github.com/guaidao2/cryptoexp.git
cd cryptoexp
python cryptoexp_cli.py analyze challenges/rsa_wiener.txt     # 直接跑命令行
python -c "import sys; sys.path.insert(0, 'src'); import cryptoexp"   # 或把 src/ 加进 PYTHONPATH
```

运行时零依赖：核心只用标准库，所以在没有包索引的内网机器上同样能跑。

---

## 快速开始

```bash
# 不需要安装任何东西
python3 cryptoexp_cli.py analyze challenges/rsa_wiener.txt
python3 cryptoexp_cli.py analyze challenges/xor_repeating.txt --solve --run
python3 cryptoexp_cli.py hypotheses challenges/rsa_high_bits.txt   # 攻击面 + 缺口
python3 cryptoexp_cli.py lab "把整段题面粘在这里"                    # 工作台脚手架
python3 cryptoexp_cli.py list                                      # 分析器 + 模板 + API 地图
```

```python
import cryptoexp as cx

cx.long_to_bytes(0x4142)              # b'AB'
cx.b64d('ZmxhZ3thfQ==')               # b'flag{a}'
cx.algebra.gcd(24, 36)                # 12
cx.lll([[1, 1, 1], [1, 0, 1], [0, 1, 1]])         # 纯 Python 格基约减
cx.known_high_bits_factor(n, p_high, 160)         # Coppersmith
cx.wiener_attack(e, n, c)                         # {'ok':..., 'plaintext':..., 'factors':...}
cx.ecb_byte_at_a_time(cx.make_ecb_oracle(key, secret))   # oracle 攻击
cx.padding_oracle_attack(valid, iv + ct)
cx.clone_from_outputs(624 个输出)                  # 克隆 MT19937 状态
cx.discrete_log(g, h, p)['x']                     # BSGS → Pohlig-Hellman
cx.dsa_nonce_reuse(p, q, g, y, r, s1, s2, h1, h2) # 随机数重用还原私钥
cx.crc_compute(b"123456789", 32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF)  # 0xCBF43926
cx.length_extension(h1, len(data), b"&admin=1", secret_len=len(secret))
cx.audit_rsa_key(n, e, extra_moduli=[other_n])    # 带等级的弱密钥审计
cx.berlekamp_massey(bits)                         # 从输出比特恢复 LFSR 抽头
cx.java_random_predict(outputs, 4)                # java.util.Random 状态恢复
```

---

## 覆盖范围（机械性操作）

| 领域 | 模块 | 你能拿到什么 |
|---|---|---|
| 数论 | `utils/algebra.py` | gcd/egcd/lcm、模逆、CRT、整数开方、Miller-Rabin、Pollard rho、连分数、Wiener、Fermat、BSGS、Tonelli-Shanks、LCG 参数恢复 |
| 模运算扩充 | `utils/modular.py` | Legendre/Jacobi/Kronecker 符号、`sqrt_mod`（素数模与合数模）、totient/Carmichael/Möbius、`order_mod`、原根、非互素 `crt_general`、列表 gcd/lcm、Pollard p-1、Williams p+1、光滑性、`binomial_mod` |
| 多项式 | `utils/polytools.py` | 多项式 divmod/gcd/求导/模 p 求根/由根构造/复合/幂模、不可约判定（Rabin）、结式、GF(2) 多项式运算（位编码） |
| GF(p) 线性代数 | `utils/gf.py` | 行简化阶梯形、求解、零空间、求逆、矩阵乘、LCG 参数求解、线性映射恢复（Hill / LFSR 类） |
| GF(2) + LFSR + CRC | `utils/gf2.py` | GF(2) 上的 RREF/秩/求解/零空间/求逆、`LFSR`、Berlekamp-Massey 恢复抽头、CRC 计算/标准目录/参数反推/**伪造**/**未知域原像**、位序工具 |
| 格 | `utils/lattice.py` | 纯 Python LLL、单变量 Coppersmith、已知高位分解、低密度子集和（LLL）与中间相遇 |
| 编码 | `utils/encoding.py` | hex/base64/base32/base58/base85/二进制、解码链搜索、单字节与重复密钥 XOR、凯撒/仿射/维吉尼亚/摩斯/栅栏（带打分） |
| 古典密码 | `utils/classic_extra.py` | Atbash、ROT47/ROT-N、Bacon、Playfair、Hill、列移位、栅栏、自动密钥、单表替换、base62/base91、URL/HTML 解码、密码指纹 |
| 分组密码 | `utils/aes.py`、`utils/pad.py`、`utils/symtools.py` | 纯 Python AES-128/192/256 的 ECB/CBC、PKCS#7、XOR、CBC 字节翻转、仅凭密文识别 ECB、推断分组大小 |
| 流密码 | `utils/stream.py` | RC4、ChaCha20（RFC 8439）、AES-CTR、密钥流重用 / crib dragging |
| 哈希 | `utils/hashes.py` | 纯 Python SHA-1/SHA-256 与**长度扩展**（`length_extension`、可续跑的 `HashState`） |
| PRNG | `utils/prng.py`、`utils/prng_extra.py` | MT19937 克隆/预测/爆破种子、Java `Random` 恢复与预测、glibc `rand` 状态恢复、xorshift 恢复、截断 LCG（格） |
| RSA 攻击 | `utils/rsa_ops.py`、`utils/rsa_attacks.py` | 小指数、广播、共模、共享素因子、Wiener、Fermat、Pollard、dp 泄露、phi 泄露、已知高位、Franklin-Reiter、带填充 Håstad、已知部分明文、奇偶/LSB oracle |
| 密钥解析 | `utils/keys.py` | PEM/DER 的 RSA 公钥与私钥解析、OpenSSH 公钥与私钥、DER 编码、SHA256 指纹 |
| 签名 | `utils/signatures.py` | ECDSA/DSA 随机数重用恢复、玩具曲线签名与验签、e=3 签名伪造、PKCS#1 v1.5 填充 |
| Oracle 攻击 | `oracle.py` | 分组大小/模式识别、未知前缀对齐、ECB 逐字节恢复、CBC padding oracle、用于练习的本地 oracle |
| 分析层 | `core/`、`hypothesis.py`、`lab.py` | 黑板上下文、双注册表、27 条带缺口上报的攻击假设、工作台脚手架生成、三态验证；分析器覆盖现已包含 **CRC**（目录查表、原像、伪造）与 **LFSR**（抽头恢复 + 密钥流），各有对应解题模板 |

---

## 为什么它不是模板库

intelpwn 那套"固定漏洞类 → 固定利用链"在 pwn 上成立，是因为类别有限。
密码学恰好相反：你要读构造、找结构性弱点，最后一步常常得自己写。
所以 cryptoexp 是分层的：

| 层 | 作用 | 位置 |
|---|---|---|
| 原语 | 可复用的积木（上面表格里的全部内容） | `src/cryptoexp/utils/*` |
| 分析 | 提取参数、判定攻击面、尝试攻击 | `src/cryptoexp/core/analysis/*` |
| 假设引擎 | 27 条显式假设，带 `needs`/缺口：哪条适用、为什么不适用、**缺哪一块信息** | `src/cryptoexp/hypothesis.py` |
| 工作台 | 可运行脚手架：参数内联、假设与缺口写成注释、起步片段、留给你自己想法的接口 | `src/cryptoexp/lab.py` |
| 解题模板 | 常见家族的快路径；生成独立可运行脚本 | `src/cryptoexp/core/solve.py` |
| 验证 | confirmed / candidate / not_reproduced 三态，含 RSA 重加密与严格 flag 匹配 | `src/cryptoexp/core/verify.py` |

模板只是便利，不是答案。机械性操作放在库里让你自由组合；长尾部分由命令行交给你
排序后的假设、缺失信息清单和一份工作台。

---

## 设计纪律（继承自 intelpwn）

- **黑板**：`analyze_all` 只物化一次上下文（文本、文件、命名参数、整数、密文块、
  已解码字节）；分析器消费它而不重复解析。单个分析器失败降级为警告，永不中断整轮。
- **双注册表**：`register_analyzer(name)` 与 `register_solver(name, predicate, gen, priority)`；
  未知键自动渲染，所以新增分析器不需要改展示层。
- **证据分级**：每个结论都带严重等级与置信度；"规则猜测"会被明确标注。
- **未知是一等状态**：假设会声明它需要什么，引擎报告缺口而不是沉默。
- **有界工作**：昂贵步骤有显式预算，预算用尽会被上报。
- **验证优先于启发式**：开发过程中发现的每个 bug 都变成了回归测试。例如：
  搜索类目标函数不得含 flag 加分（否则爬山会伪造 flag）、Coppersmith 必须拒绝
  `p = n` 这种平凡"分解"、256 位里已知 160 位需要 `m=t=3` 的 LLL 参数、
  生成的脚本必须真的能跑并打印 flag。

---

## 测试

```bash
python -m unittest discover -s tests -v
python challenges/make_challenges.py     # 重新生成靶场语料（可选）
```

`tests/test_library.py` 核对官方向量（FIPS-197 AES、RFC 8439 ChaCha20、
CRC-32/CRC-16 校验值、SHA-1/SHA-256 测试向量）、代数与格恒等式、
针对本地构造 oracle 的攻击、签名随机数重用与 MT19937 克隆。
`tests/test_toolkit.py` 覆盖机械层：模符号与非互素 CRT、多项式/GF(2) 运算、
CRC 伪造、LFSR 抽头恢复、长度扩展、RC4/ChaCha20/AES-CTR 向量、
Java/glibc PRNG 恢复、RSA 攻击封装、密钥解析与签名原语。
`tests/test_challenges.py` 是端到端：19 道靶场必须解出 flag，生成的解题脚本必须
能编译**并真的跑到 flag**，JSON 契约必须成立。
`tests/test_forensics.py` 覆盖评估层（批量 GCD、密钥审计、JWT/DER 解析、弱 PRNG 识别），
材料是构造出来的真实形态数据。
`tests/test_audit_regressions.py` 把两轮独立审计找出的每个缺陷都钉住，防止错误公式和
"看着对其实误导"的 docstring 复现。

目前合计：**248 个用例全绿**（`python -m unittest discover -s tests`）。

---

## 如实说明的边界

## API 稳定性

`0.2.0` 是第一个非预览版，所以把话说明白：**稳定**的是原语、分析器、命令行、JSON schema 与
结果字典契约 —— 这些名字和语义不会在没有废弃说明的情况下改动；**实验性但带实测边界**的是最新的
格类能力（双变量 Coppersmith、线性化格、共用 d 的 SDAP 格、ADFGX/ADFGVX 破解），它们有测试、
失败路径也诚实，但可达范围窄、且是实测值而非理论值，下一节逐条列了边界；**尚未覆盖**的是
"诚实限制"里点名的那些（真实曲线 ECC、二元以上的多元 Coppersmith、Boneh-Durfee、完整
Bleichenbacher），它们只报告缺口，不假装能做。

- `glibc_rand_recover` 需要大约 **96 个以上连续输出**。更少时被丢弃的低位确实无法唯一确定：
  函数会枚举所有与观测一致的解，只有它们在后续输出上也一致时才返回状态，否则返回 `None`。
  它从不猜。
- `lcg_recover_truncated` **不是**格基实现。当可见高位不足以唯一确定参数时它返回 `None`
  （docstring 里写了），而不是编一段序列出来。格基写法试过，没能做到可靠。
- 次数 > 1 的 Coppersmith 在纯 Python 下只在很小的格维度上可行：所以
  `stereotyped_message` 与 `hastad_padded` 会先走精确整数开方路径（消息未发生模 n 约减时，
  这也是 CTF 里最常见的形态），只有真发生回绕时才落到格上，而那里可能耗尽时间预算。
- **双变量 Coppersmith**（`coppersmith_bivariate`、`known_high_bits_two_primes`）实测是
  *每个未知量几个 bit*，`n` 到大约 384 位：12 列的 LLL 上限先于行列式允许的 `XY < N^0.4`
  卡住；512 位的 `n` 会被基大小预检直接拒绝，而不是傻跑约 74 秒。只找整数根。
  `known_high_bits_two_primes` 要传**未移位**的高位，函数自己乘 `2^shift` —— 传移位过的
  值会失败且不说明原因。
- **线性化格**（`linearize`、`recover_from_products`）处理*已确定*的线性同余系统，上限约
  12 个格坐标（4–5 个未知量），几秒内出结果，超过就拒绝。若方程组里变量只以乘积形式出现
  （单独 `x*y == c`，或 `x+y == s` 与 `x*y == c` 同给），它**解不了** —— 那类形状属于
  `coppersmith_bivariate`。`separate_variables` 只做精确算术、没有模数参数：把已证明的
  单项值还原成变量本身（`x*y^2` 与 `x^2*y` 的 gcd 是 `x*y`）。
- **多个模数共用私钥 d**（`common_d_attack`、`common_d_lattice`）在 512 位模数下实测：
  m=3 到约 2^128 位、m=4 到约 2^150；**m=2 相比 `rsa_ops` 里原有的连分数段毫无增益**，
  m=5 配 2^170 位失败。没有声称 `N^(m/(m+1))` 界——实测边界贴着格的 Gaussian heuristic。
- **ADFGX / ADFGVX**：已知方阵时，读序在 k=6（`quick`）、k=7（`normal`）、k=8（`deep`，
  约 15 秒）内穷举；k=9 在 `deep` 下偶尔能由模拟退火找到，k=11/12 未能恢复。方阵未知时，
  只有方阵关键字在候选里**且**词级证据过了一道实测阈值才给答案，否则 `ok=False`，把最好的
  往返结果作为 hypothesis 给出——单条密文在数学上定不唯一方阵。
- `scan_structured_gcd` 把普通的共享素因子与 `N±1` 结构线索分开报（只有前者能分解模数），
  低于 32 bit 的 gcd 只计数不当结论（视为噪声），并排除完全相同的模数。
- 玩具曲线以外的 ECC、Boneh-Durfee、完整 Bleichenbacher：
  要么是写了文档的骨架，要么没有 —— 工具会报告假设与缺口，而不是假装能做。
- 离散对数只有 BSGS / Pohlig-Hellman；群阶含大素因子时会如实报告不可行。
- 纯 Python 的分数 LLL 在维度 ~8 以内比较舒服；次数为 1 的 Coppersmith 默认取
  `m=t=3`（512 位 N、已知 160 位时约 6 秒）。
- oracle 类攻击需要一个回调；工作台自带远程 oracle 模板。
- 分析器已能端到端处理 **CRC** 与 **LFSR** 两类题（查表/原像/伪造；抽头恢复 + 密钥流），
  并生成解题脚本。其余新家族（ChaCha20/RC4、哈希长度扩展、Java/glibc PRNG、密钥、签名）
  目前是**库 + 单元测试**级覆盖并带官方向量，还没接进命令行路由：这些请直接组合库调用
  （或使用假设/工作台层）。
- CRC 原像只在 `8 * unknown_len <= width` 时能唯一确定未知域（CRC-32 下 4 字节、
  CRC-16 下 2 字节）。未知更多时它返回一个 CRC 对得上的解并标注 `unique: False` ——
  有多个字节串都符合，所以它不能声称找到了原来那一个。
- Playfair / Hill / 列移位 / Bacon 天生有损（补 X、I/J 与 U/V 合并），
  所以那里的"往返"指的是 `decrypt(encrypt(x)) == prepared(x)`。
- 暂时没有 Web 界面。CI 会在 Linux 上跑 3.10 与 3.12 两套测试，并在推 `v*` tag 时通过
  trusted publishing 自动发布到 PyPI，发布环节不需要保存任何 token。

License: MIT — coolmoon & guaidao2。
