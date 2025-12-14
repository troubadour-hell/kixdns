use std::fs;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use ipnet::IpNet;
use serde::Deserialize;
use tracing::info;

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineConfig {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub settings: GlobalSettings,
    /// 多维优先级的 pipeline 选择规则（按顺序评估）。
    #[serde(default)]
    pub pipeline_select: Vec<PipelineSelectRule>,
    #[serde(default)]
    pub pipelines: Vec<Pipeline>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct GlobalSettings {
    /// 最小TTL秒数，缺省0。
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u32,
    /// UDP监听地址，缺省0.0.0.0:5353，避免1024以下端口权限问题。
    #[serde(default = "default_bind_udp")]
    pub bind_udp: String,
    /// TCP监听地址，缺省0.0.0.0:5353。
    #[serde(default = "default_bind_tcp")]
    pub bind_tcp: String,
    /// 默认上游DNS。
    #[serde(default = "default_upstream")]
    pub default_upstream: String,
    /// 上游超时（毫秒）。
    #[serde(default = "default_upstream_timeout_ms")]
    pub upstream_timeout_ms: u64,
    /// 响应阶段 Pipeline 跳转上限。
    #[serde(default = "default_response_jump_limit")]
    pub response_jump_limit: u32,
    /// UDP 上游连接池大小。
    #[serde(default = "default_udp_pool_size")]
    pub udp_pool_size: usize,
    /// TCP 上游连接池大小。
    #[serde(default = "default_tcp_pool_size")]
    pub tcp_pool_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Pipeline {
    pub id: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub matchers: Vec<MatcherWithOp>,
    #[serde(default = "default_match_operator")]
    pub matcher_operator: MatchOperator,
    #[serde(default)]
    pub actions: Vec<Action>,
    /// 响应阶段匹配器，可根据上游、响应类型、rcode等进行判断。
    #[serde(default)]
    pub response_matchers: Vec<ResponseMatcherWithOp>,
    #[serde(default = "default_match_operator")]
    pub response_matcher_operator: MatchOperator,
    /// 响应匹配成功后执行的动作序列。
    #[serde(default)]
    pub response_actions_on_match: Vec<Action>,
    /// 响应匹配失败后执行的动作序列。
    #[serde(default)]
    pub response_actions_on_miss: Vec<Action>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Matcher {
    Any,
    /// 匹配域名后缀，大小写不敏感。
    DomainSuffix {
        value: String,
    },
    /// 域名正则匹配（Rust 正则语法，默认大小写不敏感请自行使用 (?i)）。
    DomainRegex {
        value: String,
    },
    /// 匹配客户端IP的CIDR。
    ClientIp {
        cidr: String,
    },
    /// 匹配查询 QCLASS（如 IN/CH/HS）。
    Qclass {
        value: String,
    },
    /// 是否存在 EDNS 伪记录。
    EdnsPresent {
        expect: bool,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PipelineSelectorMatcher {
    /// 入口标签匹配（来自启动参数 listener_label）。
    ListenerLabel { value: String },
    /// 客户端IP CIDR。
    ClientIp { cidr: String },
    /// 请求域名后缀。
    DomainSuffix { value: String },
    /// 请求域名正则。
    DomainRegex { value: String },
    /// 任意请求（总是匹配）。
    Any,
    /// 请求 QCLASS（如 IN/CH/HS）。
    Qclass { value: String },
    /// 请求是否携带 EDNS。
    EdnsPresent { expect: bool },
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineSelectRule {
    pub pipeline: String,
    #[serde(default)]
    pub matchers: Vec<PipelineSelectorMatcherWithOp>,
    #[serde(default = "default_match_operator")]
    pub matcher_operator: MatchOperator,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatcherWithOp {
    #[serde(default = "default_match_operator")]
    pub operator: MatchOperator,
    #[serde(flatten)]
    pub matcher: Matcher,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineSelectorMatcherWithOp {
    #[serde(default = "default_match_operator")]
    pub operator: MatchOperator,
    #[serde(flatten)]
    pub matcher: PipelineSelectorMatcher,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseMatcherWithOp {
    #[serde(default = "default_match_operator")]
    pub operator: MatchOperator,
    #[serde(flatten)]
    pub matcher: ResponseMatcher,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseMatcher {
    /// 匹配使用的上游（字符串相等）。
    UpstreamEquals { value: String },
    /// 复用请求域名后缀匹配（便于上游+域名组合策略）。
    RequestDomainSuffix { value: String },
    /// 请求域名正则匹配。
    RequestDomainRegex { value: String },
    /// 匹配响应所来自的上游 IP（支持 CIDR）。
    ResponseUpstreamIp { cidr: String },
    /// 匹配响应 Answer 中的 IP 地址（A/AAAA 记录，支持 CIDR）。
    ResponseAnswerIp { cidr: String },
    /// 匹配响应记录类型（如 A/AAAA/CNAME/TXT/MX 等）。
    ResponseType { value: String },
    /// 匹配响应的RCode（如 NOERROR/NXDOMAIN/SERVFAIL）。
    ResponseRcode { value: String },
    /// 匹配请求 QCLASS（如 IN/CH/HS）。
    ResponseQclass { value: String },
    /// 响应是否携带 EDNS。
    ResponseEdnsPresent { expect: bool },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// 记录日志，level可选：trace/debug/info/warn/error
    Log { level: Option<String> },
    /// 固定响应rcode（如 NXDOMAIN/NOERROR）。
    StaticResponse { rcode: String },
    /// 返回固定 IP (A/AAAA)。
    StaticIpResponse { ip: String },
    /// 跳转到指定 Pipeline 继续处理。
    JumpToPipeline { pipeline: String },
    /// 终止匹配。请求阶段使用默认上游，响应阶段使用当前响应。
    Allow,
    /// 终止并丢弃（返回 REFUSED）。
    Deny,
    /// 透传上游；upstream为空则使用全局默认；transport缺省udp。
    Forward {
        upstream: Option<String>,
        #[serde(default)]
        transport: Option<Transport>,
    },
    /// 继续匹配后续规则。响应阶段会复用当前响应结果。
    Continue,
}

#[derive(Debug, Clone, Deserialize, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Deserialize, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MatchOperator {
    And,
    Or,
    #[serde(alias = "not", alias = "and_not", alias = "and-not", alias = "andnot")]
    AndNot,
    #[serde(alias = "or_not", alias = "or-not", alias = "ornot")]
    OrNot,
    /// Backward compatibility placeholder (not constructed)
    #[serde(skip)]
    #[allow(dead_code)]
    Not,
}

fn default_match_operator() -> MatchOperator {
    MatchOperator::And
}

pub fn load_config(path: &Path) -> Result<PipelineConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read config file: {}", path.display()))?;
    let mut cfg: PipelineConfig = serde_json::from_str(&raw)
        .with_context(|| format!("parse config file: {}", path.display()))?;

    if let Some(version) = cfg.version.as_ref() {
        info!(target = "config", version = %version, "config loaded");
    }

    // 轻量校验：CIDR提前解析，便于后续快速匹配。
    for pipeline in &mut cfg.pipelines {
        for rule in &mut pipeline.rules {
            for matcher in &rule.matchers {
                if let Matcher::ClientIp { cidr } = &matcher.matcher {
                    let _parsed: IpNet = cidr.parse()?;
                }
            }
            for matcher in &rule.response_matchers {
                if let ResponseMatcher::RequestDomainSuffix { value } = &matcher.matcher {
                    if value.is_empty() {
                        anyhow::bail!("response_matcher request_domain_suffix empty");
                    }
                }
                if let ResponseMatcher::ResponseUpstreamIp { cidr } = &matcher.matcher {
                    for part in cidr.split(',') {
                        let s = part.trim();
                        if !s.is_empty() {
                            let _parsed: IpNet = s.parse()?;
                        }
                    }
                }
                if let ResponseMatcher::ResponseAnswerIp { cidr } = &matcher.matcher {
                    for part in cidr.split(',') {
                        let s = part.trim();
                        if !s.is_empty() {
                            let _parsed: IpNet = s.parse()?;
                        }
                    }
                }
            }
        }
    }

    for sel in &cfg.pipeline_select {
        for m in &sel.matchers {
            if let PipelineSelectorMatcher::ClientIp { cidr } = &m.matcher {
                let _parsed: IpNet = cidr.parse()?;
            }
        }
    }

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn response_action_fields_default_to_empty() {
        let raw = json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": [
                        {
                            "name": "rule",
                            "actions": [ { "type": "log", "level": "info" } ]
                        }
                    ]
                }
            ]
        });
        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let rule = &cfg.pipelines[0].rules[0];
        assert!(rule.response_actions_on_match.is_empty());
        assert!(rule.response_actions_on_miss.is_empty());
    }

    #[test]
    fn rule_operator_defaults_to_and_when_omitted() {
        let raw = serde_json::json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": [
                        {
                            "name": "rule",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { "type": "log", "level": "info" } ]
                        }
                    ]
                }
            ]
        });

        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let rule = &cfg.pipelines[0].rules[0];
        // default should be MatchOperator::And
        assert_eq!(rule.matcher_operator, MatchOperator::And);
        assert_eq!(rule.response_matcher_operator, MatchOperator::And);
    }
}

fn default_min_ttl() -> u32 {
    0
}

fn default_bind_udp() -> String {
    "0.0.0.0:5353".to_string()
}

fn default_bind_tcp() -> String {
    "0.0.0.0:5353".to_string()
}

fn default_upstream() -> String {
    "1.1.1.1:53".to_string()
}

fn default_upstream_timeout_ms() -> u64 {
    2000
}

fn default_response_jump_limit() -> u32 {
    10
}

fn default_udp_pool_size() -> usize {
    64
}

fn default_tcp_pool_size() -> usize {
    64
}
