图片抓取服务加了域名白名单，攻击者用自己的域名照样读到了内网接口：白名单用后缀比较，evil-example.com 命中 example.com；通配条目匹配裸域本身；只校验域名不校验解析出的地址，指向内网也能过；私网判定只覆盖十点零段，回环与链路本地漏判；解析与连接各做一次，攻击者可在两次之间改结果；重定向不重新校验，最终跳到内网；协议白名单缺失，文件协议也能读；策略校验不检查是否允许无限重定向；批量校验复用解析缓存，后一个地址命中前一个结果；端口不校验，只允许四四三但实际连任意端口。engine/fetch/guard.py 是核心，tests/fetch/test_guard.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式
在仓库根目录执行：
    pytest tests -q
预期输出为 15 failed，无 error，无 collection error。

自检输出尾部示例：
    15 failed in 0.xxs

字段表
领域：安全
方向：漏洞检测与攻防
任务类型：Bugfix
技术栈：Python 3, pytest
外部依赖：无外部依赖

tests 约束
tests/fetch/test_guard.py 恰好包含 15 个测试，交付后不可修改。实现者只能补全 engine/fetch/guard.py 中的 8 个桩，不得通过改测试、删测试、跳过测试或放宽断言获得通过。测试不联网、不使用随机数，所有解析结果都通过参数注入的 resolver 提供。

目录布局
本仓库采用 engine 嵌套布局：实现包位于 engine/fetch，测试位于 tests/fetch，两层目录镜像对应。仓库根的 conftest.py 只负责把仓库根加入 sys.path，使 from engine.fetch.guard import ... 可用。核心实现文件是 engine/fetch/guard.py，测试入口是 tests/fetch/test_guard.py。
## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

