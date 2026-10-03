# IntelPwn 项目思想研究笔记

- 对象：`https://github.com/guaidao2/intelpwn`（作者：guaidao2 / 玄幕安全团队，MIT）
- 克隆方式：`git clone https://gh-proxy.org/https://github.com/guaidao2/intelpwn.git`
- 本地路径：`D:\编程\cryptokit\intelpwn`
- 版本：HEAD = `f78940e`，共 114 个 commit，提交日期跨度 2026-07-03 → 2026-08-16
- 规模：`intelpwn/core/analysis/` 下 18 个分析模块；最重单文件 `core/exploit.py` 1533 行；`tests/` 195 个用例
- 本地复核环境：Windows + Python 3.11.7 + pwntools 4.15 / capstone / pyelftools
  —— **非目标环境**（该工具面向 Kali/Linux，需要 checksec/objdump/readelf/gdb），结果只作交叉参考

---

## 一句话概括

IntelPwn 不是"给 checksec 套个壳"，而是把 pwn 流程拆成一条**可解释的判定流水线**：
`反汇编 → 指令级语义判定（含置信度）→ 动态交叉验证 → 按优先级路由生成可运行 exploit → 三端展示`，
并且把"我不知道"当成一等结果贯穿全程，而不是硬凑一个结论。

---

## 一、四条核心思想（思想本身，不是功能清单）

### 1. 纯算法、零 ML —— 结论必须可追溯到具体判据

作者把"没有模型依赖、可解释、可复现"写进设计理念（README 设计理念 §1）。
落到代码上是**指令级数据流 + 数值比较**，而不是模式匹配：

- 语义层 v2（`analysis/overflow.py:85-207`）：把"匹配指令"升级为"匹配语义关系"。
  `_buf_stack_offset()` 沿 `mov/lea` 链回溯缓冲寄存器的定义，`_size_value()` 回溯大小寄存器，
  遇 `call/jmp/ret` 截断路径（跨函数数据流不算本函数），回溯上限 200 条防 O(N²)。
  编译器把 `lea` 提前几百条、寄存器换用（`lea rax,[rbp-0x40] → mov rsi,rax`）都追得到 —— 这正是"固定窗口正则"做不到的。
- 溢出判定是**算术**而不是"像不像"：有界读必须 `arg_size > buf_off + 16` 才算危险（`overflow.py:515-522`）；
  大小无法静态确定时只敢在"目标确认在栈上"时报，且置信度降为"中"。
- 注释引擎同理（`analysis/comments.py:1-5`）：红色注释只在"分析结论给出的数字 + 指令级寄存器约定"同时成立时出现，
  所以红只能是对结论的回声，不可能是猜测。

### 2. 证据分级 + 不确定不下结论 —— 这是整个项目最一致的品味

同一件事在不同层反复出现，都是同一句话："不知道"要单独成一个状态，不许混进"有/没有"。

- 三级注释按**证据来源**分级而不是按严重程度（`analysis/comments.py:1-5`）：
  红 = 分析结论直接映射；黄 = 规则猜测，措辞强制自带"若…则"（`comments.py:213-227`）；
  灰 = 通用汇编语义。黄不能覆盖红，灰只在 `level is None` 时兜底。
- 语义查询返回 `UNKNOWN = None`（`overflow.py:95`），一路传下去，交给 angr 兜底或动态验证补。
- angr 兜底自带**合理性与资源闸门**（`analysis/semantic_angr.py:13-14, 52-68`）：
  每次 analyze 最多 3 次求值、二进制 > 500KB 直接跳过（防止符号执行打爆内存）；
  算出大小落在 `0 < v < 0x10000` 之外（垃圾大数）视为不可靠 → 返回 None 走保守分支。
- 交叉验证是**七态**而不是布尔（`core/cross_validate.py:1-13`），并且写明原则：
  "崩了是强证据（确认），没崩是弱信号（只能降级不能否定）"。
  于是"未复现"的 note 明确写"可能输入构造不完整，不否定静态发现"；
  崩溃但提取不到偏移单独判"崩溃未关联"，明说可能是无关的启动崩溃。
- 结论排序即优先级（`cross_validate.py:124-139`）：动态发现 > 冲突 > 崩溃未关联 > canary > 未复现 > 确认。
  "静态盲区/冲突"永远压过"确认"，不允许一好遮百丑。
- 动态验证自己也很克制（`core/verify.py`）：崩溃判据只有 `Program received signal`（正常退出打印 `Program exited normally`，不会误判）；
  偏移提取顺序写成注释里的**实证结论**——"gdb 的 rip 常显示 ret 指令本身，`cyclic_find(rip)` 恒失败，所以先取 `$rsp` 指向值"。
  这是踩坑后改判据顺序，而不是加特例。

### 3. 三端口插件化 + 黑板 —— 新能力零改核心

`results` dict 是唯一的通信渠道，一个能力包 = 三个"口子"（`CONTRIBUTING.md` §2）：

1. **分析器口子**：`@register_analyzer("name")`（`analysis/__init__.py:37-63`），
   插件跑在内置流程之后，结果写 `results[name]`；单个插件抛异常兜成 `{"error": ...}`，不影响别人。
2. **exploit 模板口子**：`register_exploit_template(name, predicate, gen, priority)`（`core/exploit.py:40-53`），
   按 priority 路由（内置 10–110、插件默认 500、骨架 999；`priority=5` 可覆盖内置）。
   内置 11 个模板就是注册表里的一组条目（`exploit.py:1258-1478`），`generate()` 只做"第一个 predicate 命中即用"（`:1511-1514`）。
   值得学的取舍：predicate 里显式写互斥条件（例如 ret2libc 排除"已被 shellcode/ret2system 覆盖"的情形），
   而不是靠 if-elif 顺序隐含表达。
3. **展示层兜底**：CLI 用 `_RENDERED_KEYS` 白名单做**排除法**（`core/report.py:20-26, 47-74`），
   Web 用 `KNOWN_KEYS` 之外的 key 自动生成"其他发现"折叠卡片（`webui/static/app.js:228-238`）。
   新增分析器不需要改 report.py / app.js。
   （边界：白名单是硬编码的，插件若复用名单内已有 key 会被静默跳过——通配只覆盖新 key。）

**黑板（基础设施缓存）**是这套东西的粘合剂：`analyze_all` 一次性物化
`_shared = {insns, bits, func_bounds, sym_by_addr, plt_map}`（`analysis/__init__.py:94-131, 161-168`），
overflow / win_targets / heap_uaf / global_writes 消费它，避免大静态二进制重复 4–5 次 `open_elf` + capstone 全量反汇编。
但它不是硬依赖：模块单独调用时能自建兜底（menu 会补建并写回黑板），并有 `tests/test_blackboard.py` 断言"黑板路径与独立自扫结果一致"——
即"缓存优化不许引入静默漏检"。这是很多工具做缓存时忘掉的那条回归。

### 4. 误报比漏报更被当成回归

防误报几乎全靠**排除法**，而不是更聪明的正则：

- 无 printf 族直接排除格式化字符串（`analysis/fmtstr.py:129-142`）——针对"堆题菜单回显把十六进制当泄漏"的历史误报。
- 菜单识别里"识别到选项"≠"敢自动交互"：只有 handler 命中 overflow 报出的函数/地址才置 `confident`（`analysis/menu.py:420-433`）；
  打印调用（puts/printf）不算 handler（`menu.py:414-415`）；"只 read+转数字、无业务调用"的函数不被当成 handler（`menu.py:319-327`）。
- 全局写入与栈溢出**分账**：`strcpy` 到全局段由 `detect_global_writes` 单独报（`overflow.py:263-312`），
  不污染栈溢出结果（`overflow.py:524-530` 注释写明）。
- 入参不当缓冲：`[rbp+8]` 明确排除（`overflow.py:112-122`）。
- 拒绝回答的地方就拒绝：x86 PIC 的 `jmp [ebx+disp]` 静态不可解 → 保守跳过（`analysis/win_targets.py`）；
  无 PLT 就不猜 free/use（`heap_uaf.py:129-130`）；非静态链接不跑 static_libc。
- 接受并标注误报：callgraph 承认"用户自定义的同名 wrapper（如 read）也会标橙，属误报扩大但可接受"；
  heap_uaf 只比数组基址不比下标——误差方向写在注释里，比藏起来好。
- 连输出侧都假设恶意：读字符串时过滤控制字节，防止样本里注入 ANSI/OSC 转义打终端（`win_targets.py`）。

---

## 二、几个有辨识度的具体设计

| 设计 | 位置 | 为什么值得记 |
|---|---|---|
| padding 用"危险调用的缓冲偏移"而非"函数最大 lea" | `overflow.py:546-559` | 多 lea 场景下前者才准（choice 槽 0x28 vs read buf 0x20 → 40 而非 48） |
| 三重 padding 验证 + 一致时跳过 GDB | `overflow.py:626-665` | 静态与 objdump 一致（90%+）就直接返回"高置信"，省 2s |
| 跨函数 UAF = "同一全局数组基址 + 不同函数里 free/use" | `heap_uaf.py:135-173` | 不依赖符号名与菜单语义；stripped 用 endbr64/ret 切匿名函数，否则"跨函数"根本判不出来 |
| 堆分析 + 菜单识别合成出"选项 2→3" | `analysis/__init__.py:257-280` | 静态结果互相翻译成人话，这是"模块间协作"的样板 |
| glibc 版本 → 攻击面行为表 | `analysis/glibc_meta.py` | 输出不是元数据而是决策依据（<2.34 hook 可用 / ≥2.34 走 tls_dtor_list、IO_FILE） |
| ret2win 自动补 ret 对齐 | `exploit.py:176-215` | SysV 要求 call 前 rsp 16 对齐，否则 glibc `movaps` 崩——这种"模板看起来对但必崩"的坑被专门修过 |
| 诚实标注 `[骨架]` / `# [WARN]` | `exploit.py:1211-1255` | 明确"不输出看似可用实则必崩的脚本" |
| verify 自动模式用双信号判打穿 | `verify.py:113-143` | LEAK = UAF 复现，PWN = uid/root；于是能产出"泄露确认"这种中间态 |

---

## 三、开发方法论（从 114 条 commit 读出来的）

- **每条功能 commit 自带验收证据**：几乎都是 "Kali N passed" + 实测打穿/复现的结论（例如 "实测打穿 (cat flag 执行)"、
  "duck 实测 UAF: 选项2→选项3"）。测试数与功能数被当进度指标在 commit message 里滚动。
- **自我审查文化**：约 23 条 commit 与 review 相关（`fix review` / `fix security_review MEDIUM` / `fix review blocking`），
  另有 commit 明确写 "subagent root cause"——用子 agent 做审查与定位。
- **诚实记录踩坑与回退**：如 "`SHF_WRITE=1` 修正（`&3` 误标 .rodata/.text）"、
  "`protocol_version=HTTP/1.0`（keep-alive 线程 park 导致 Ctrl-C 杀不掉）"、
  "README 禁止 emoji"（文档一致性约定）。
- **没有 CI**（仓库无 `.github`）：全量验证靠在 Kali/Ubuntu 上人工跑，每条 commit 自带"N passed"的数字，
  这是作者的明确取舍（不改核心行为就不会有回归，但每步都要人盯）。
- **文档即契约**：CONTRIBUTING.md 把黑板协议、三端口、测试规范、提交流程写死，并明确"新增分析器必须带单测"。

---

## 四、跑起来的两个正面复核（在 Windows 上做的，只作交叉参考）

> **前提说明**：这是个标准的 Kali/Linux 工具（依赖 checksec / objdump / readelf / gdb / pwntools / angr），
> 目标环境是 Linux。这里所有结果都是在 Windows 上顺手跑的，**不代表项目在目标环境的表现**，
> 也不作为缺陷依据；没有 Linux 环境就不该拿它下结论。

- `challenges/challenge_ret2win` → `overflow: [{function: vulnerable, padding: 72}]`，与 README 声称的 72 一致。
- `challenges/mini_configd` → `overflow: []` + `全局缓冲写入: strcpy 写入全局段 0x404080`，
  与最新 commit 声称的能力一致（固件配置解析 off-by-one 的真实场景模拟）。

这两条恰好说明一件事：它的**黑板路径**（pyelftools 解析 PLT）是能独立工作的，
所以在缺一堆 Linux 工具的机器上，主流程照样给出了正确答案。

（唯一记一笔的环境边界，与项目无关的判断：`fmtstr.py` 的 `_run_payload` 把 `OSError`
——即"这个 ELF 在当前系统上根本执行不了"——与 `TimeoutExpired` 都记成 `timed_out`，
而超时会被当作漏洞证据。在 Kali 上二进制可执行，这条不成立；只在非目标环境才浮出来。）

---

## 五、两处与环境无关的小观察（供参考，不是缺陷报告）

1. **schema 与实现漂移**：`schema/intelpwn.schema.json` 的 `cross_validation.entries[].state` 枚举里没有"泄露确认"，
   但实现会产出（`cross_validate.py:112`）且已被测试断言（`tests/test_cross_validate.py:141`）。
   schema 运行时不参与校验（全仓库没有 jsonschema 调用），属文档契约漂移，不影响运行。
2. **测试数三处不一致**：README 写 193，CONTRIBUTING 写 158，commit message 写 194（Linux 全量）。
   这是文档跟着功能滚动时的正常滞后，记一笔是因为它是"文档即契约"策略的自然代价。

另外两处**架构观察，不算问题**：
`callgraph.py` 是全项目唯一没消费黑板 `_shared` 的分析模块（`analyze_all` 不调用它，只在 web 接口按需用，
自带 `_func_bounds_local/_sym_map_local` 兜底）；`--web` 默认绑 0.0.0.0 是作者明确的知情取舍，
文档和启动提示都写了"敌对网络请用 `--web-host 127.0.0.1`"。

---

## 附：判断依据索引（都在仓库内）

- 设计理念与对比：`readme.md` 的"设计理念""与同类工具对比""算法优化"
- 插件协议：`CONTRIBUTING.md` §2–§7
- 编排与黑板：`intelpwn/core/analysis/__init__.py:94-286`
- 语义层：`intelpwn/core/analysis/overflow.py:85-207`
- angr 兜底闸门：`intelpwn/core/analysis/semantic_angr.py:13-14, 52-68`
- 交叉验证七态：`intelpwn/core/cross_validate.py:1-141`
- 动态验证：`intelpwn/core/verify.py:34-143`
- 注释分级：`intelpwn/core/analysis/comments.py:1-5, 116-264`
- 模板路由：`intelpwn/core/exploit.py:36-53, 1258-1533`
