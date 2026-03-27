# EKS 集群健康体检工具 (EKS Health Check Tool)

一个基于 Python 的 EKS 集群健康体检 POC 工具，通过主动扫描集群配置，结合 AI 分析能力，输出结构化的 Markdown 优化建议报告。

## 功能概览

- **配置扫描**：通过 Kubernetes API 和 AWS API 自动采集集群配置数据
- **四维度检查**：基础架构、网络、安全合规、应用适配性，共 23 条检查规则
- **AI 智能分析**：使用 Amazon Bedrock (Claude) 进行关联分析，生成上下文适配的优化建议
- **优雅降级**：权限不足时跳过对应资源，AI 不可用时回退到模板化建议
- **结构化报告**：输出包含评分、风险分布、优化建议的 Markdown 报告

## 检查项一览

| 维度 | 规则 ID | 检查项 | 风险等级 |
|------|---------|--------|----------|
| 基础架构 | INFRA-001 | 节点组实例类型多样性 | Warning |
| 基础架构 | INFRA-002 | 可用区分布 | Warning |
| 基础架构 | INFRA-003 | 节点资源利用率 | Warning |
| 基础架构 | INFRA-004 | 自动伸缩组件 (Karpenter/CA) | Info |
| 基础架构 | INFRA-005 | EKS 集群版本生命周期 | Warning |
| 网络 | NET-001 | VPC CNI 配置参数 | Info |
| 网络 | NET-002 | CoreDNS ndots 配置 | Warning |
| 网络 | NET-003 | CoreDNS 副本数与集群规模匹配 | Warning |
| 网络 | NET-004 | NodeLocal DNSCache | Info |
| 网络 | NET-005 | 子网可用 IP 地址 | Critical |
| 网络 | NET-006 | Security Group 过度开放 | Warning |
| 安全合规 | SEC-001 | 审计日志启用状态 | Warning |
| 安全合规 | SEC-002 | API Server endpoint 访问策略 | Info |
| 安全合规 | SEC-003 | API Server 纯 Public 无 CIDR 限制 | Critical |
| 安全合规 | SEC-004 | Secrets envelope encryption | Warning |
| 安全合规 | SEC-005 | 节点组 AMI 版本 | Warning |
| 安全合规 | SEC-006 | aws-node 默认 IAM 角色使用 | Warning |
| 应用适配性 | WORK-001 | Pod 资源 request/limit 配置 | Warning |
| 应用适配性 | WORK-002 | 资源 request 与 limit 差异 (>3x) | Warning |
| 应用适配性 | WORK-003 | PodDisruptionBudget 配置 | Info |
| 应用适配性 | WORK-004 | HPA 配置合理性 | Warning |
| 应用适配性 | WORK-005 | 健康检查探针配置 | Warning |
| 应用适配性 | WORK-006 | Pod Identity / IRSA 使用 | Critical |

## 环境要求

- Python 3.11+
- 已配置 `kubectl` 访问目标 EKS 集群（kubeconfig）
- 已配置 AWS CLI 凭证，具备以下权限：
  - `eks:DescribeCluster`, `eks:ListNodegroups`, `eks:DescribeNodegroup`
  - `ec2:DescribeSubnets`, `ec2:DescribeSecurityGroups`
  - `iam:GetRole`
  - （可选）`bedrock:InvokeModel` — 用于 AI 智能分析

## 安装

```bash
# 克隆仓库
git clone git@github.com:justin007755/eks_health_check.git
cd eks_health_check

# 安装依赖（推荐使用虚拟环境）
python -m venv .venv
source .venv/bin/activate

pip install -e .
```

安装开发依赖（用于运行测试）：

```bash
pip install -e ".[dev]"
```

## 使用方法

### 基本用法

```bash
python -m eks_health_check --cluster <集群名称> --region <AWS区域>
```

### 完整参数

```bash
python -m eks_health_check \
  --cluster my-eks-cluster \
  --region us-east-1 \
  --kubeconfig ~/.kube/config \
  --output health_report.md \
  --skip-ai
```

| 参数 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `--cluster` | 是 | — | 目标 EKS 集群名称 |
| `--region` | 是 | — | AWS Region |
| `--kubeconfig` | 否 | 默认 kubeconfig | 自定义 kubeconfig 路径 |
| `--output` | 否 | `health_report.md` | 报告输出文件路径 |
| `--skip-ai` | 否 | `false` | 跳过 AI 分析，仅使用模板化建议 |

### 示例

扫描 `us-west-2` 区域的 `prod-cluster` 集群，跳过 AI 分析：

```bash
python -m eks_health_check \
  --cluster prod-cluster \
  --region us-west-2 \
  --skip-ai \
  --output prod_health_report.md
```

执行过程输出：

```
[1/4] 扫描集群配置: prod-cluster (us-west-2) ...
[2/4] 执行检查规则 ...
  检查完成: 23 项, 通过 15 项
[3/4] 生成优化建议 ...
  生成 8 条建议
[4/4] 生成报告 ...
报告已保存至: prod_health_report.md
```

## 报告说明

生成的 Markdown 报告包含以下章节：

1. **执行摘要** — 扫描时间、集群基本信息、检查项总数、各风险等级问题数量
2. **维度评分** — 四个维度的独立评分 (0-100) 和综合健康评分
3. **检查项明细** — 按风险等级从高到低排序，包含当前值、建议值和优化建议
4. **风险分布统计** — Critical / Warning / Info 的数量分布
5. **优化建议列表** — 每条建议包含问题描述、优化步骤和预期收益
6. **附录** — 跳过的资源列表

### 评分算法

```
维度评分 = 100 - (Critical数 × 20 + Warning数 × 10 + Info数 × 3)

综合评分 = 加权平均
  权重: 基础架构=0.25, 网络=0.25, 安全合规=0.30, 应用适配性=0.20
```

## 运行测试

```bash
# 运行全部测试
python -m pytest tests/ -v

# 仅运行 CLI 集成测试
python -m pytest tests/test_cli.py -v

# 运行特定模块测试
python -m pytest tests/test_checkers.py -v
python -m pytest tests/test_scanner.py -v
python -m pytest tests/test_analyzer.py -v
python -m pytest tests/test_report.py -v
```

所有测试使用 mock 模拟外部 API 调用，无需真实 EKS 集群环境。

## 项目结构

```
eks_health_check/
├── pyproject.toml           # 项目依赖和元数据配置
├── README.md                # 本文档
├── .gitignore
├── __init__.py
├── __main__.py              # python -m eks_health_check 入口
├── cli.py                   # CLI 参数解析和流程编排
├── models.py                # 核心数据模型
├── check_rules.yaml         # 检查规则配置（23 条规则）
├── scanner/                 # Config Scanner 配置扫描层
│   ├── k8s_collector.py     #   Kubernetes API 采集
│   ├── aws_collector.py     #   AWS API 采集
│   └── config_scanner.py    #   聚合扫描入口
├── checkers/                # Check Engine 检查引擎层
│   ├── base.py              #   BaseChecker ABC + CheckEngine
│   ├── infrastructure.py    #   基础架构检查
│   ├── network.py           #   网络检查
│   ├── security.py          #   安全合规检查
│   └── workload.py          #   应用适配性检查
├── analyzer/                # AI Analyzer 智能分析层
│   ├── ai_analyzer.py       #   Bedrock AI 分析 + fallback
│   └── template_engine.py   #   模板化建议生成
├── report/                  # Report Generator 报告生成层
│   ├── score_calculator.py  #   评分计算
│   ├── markdown_renderer.py #   Markdown 渲染
│   ├── report_parser.py     #   报告解析（round-trip 验证）
│   └── report_generator.py  #   报告生成编排
└── tests/                   # 单元测试和集成测试
    ├── test_models.py       #   数据模型测试
    ├── test_scanner.py      #   Config Scanner 测试
    ├── test_checkers.py     #   Check Engine 测试
    ├── test_analyzer.py     #   AI Analyzer 测试
    ├── test_report.py       #   Report Generator 测试
    └── test_cli.py          #   CLI 集成测试
```

## 架构

```
CLI 入口
  │
  ├── Config Scanner（配置扫描层）
  │     ├── K8s API Collector
  │     └── AWS API Collector
  │
  ├── Check Engine（检查引擎层）
  │     ├── Infrastructure Checker
  │     ├── Network Checker
  │     ├── Security Checker
  │     └── Workload Checker
  │
  ├── AI Analyzer（智能分析层）
  │     ├── Bedrock Client (Claude)
  │     └── Template Engine (fallback)
  │
  └── Report Generator（报告生成层）
        ├── Score Calculator
        └── Markdown Renderer
              └── health_report.md
```

## 许可证

本项目为 POC 工具，仅供内部评估使用。
