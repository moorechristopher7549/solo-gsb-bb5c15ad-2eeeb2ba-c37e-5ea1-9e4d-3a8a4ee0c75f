"""FastAPI 应用：IPv4 CIDR 遮蔽分析 API。"""
from __future__ import annotations

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

from .analyzer import InvalidCIDRError, analyze_rules, parse_cidr_v4

app = FastAPI(
    title="IPv4 遮蔽分析 API",
    description=(
        "接收有序的 allow/deny CIDR 规则，计算每条规则未被此前规则覆盖的"
        "地址集合，按 **全生效 (full)** / **部分遮蔽 (partial)** / "
        "**完全遮蔽 (shadowed)** 分类，并将剩余集合无损压缩为数量最少的 CIDR。"
    ),
    version="1.0.0",
)


class Rule(BaseModel):
    """单条规则：动作 + IPv4 CIDR。"""

    action: Literal["allow", "deny"] = Field(
        ..., description="动作，仅允许 allow 或 deny（大小写不敏感）"
    )
    cidr: str = Field(
        ...,
        description="IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )

    @field_validator("action", mode="before")
    @classmethod
    def normalize_action(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        # 校验并规范化；非法 CIDR / IPv6 抛出 ValueError -> 422
        return parse_cidr_v4(value)[2]


class AnalyzeRequest(BaseModel):
    """分析请求：有序规则列表，至少 1 条。"""

    rules: list[Rule] = Field(..., min_length=1, description="有序规则列表（按序处理）")


class RuleResult(BaseModel):
    index: int = Field(..., description="规则在输入中的序号（从 0 开始）")
    action: Literal["allow", "deny"]
    cidr: str = Field(..., description="规范化后的规则 CIDR")
    status: Literal["full", "partial", "shadowed"]
    status_label: str = Field(..., description="状态中文说明")
    total_addresses: int
    covered_addresses: int = Field(..., description="被此前规则遮蔽的地址数")
    effective_addresses: int = Field(..., description="本规则实际生效的地址数")
    effective_cidrs: list[str] = Field(
        ..., description="生效地址集合无损压缩后的最少 CIDR 列表（空表示完全遮蔽）"
    )


class Summary(BaseModel):
    full: int
    partial: int
    shadowed: int
    effective_allow_addresses: int = Field(..., description="汇总生效的 allow 地址数")
    effective_deny_addresses: int = Field(..., description="汇总生效的 deny 地址数")


class AnalyzeResponse(BaseModel):
    rule_count: int
    rules: list[RuleResult]
    summary: Summary


@app.get("/", tags=["meta"])
def root() -> dict:
    """服务信息。"""
    return {
        "service": "ipv4-shadow-analyzer",
        "docs": "/docs",
        "openapi": "/openapi.json",
        "health": "/health",
    }


@app.get("/health", tags=["meta"])
def health() -> dict:
    """健康检查。"""
    return {"status": "ok"}


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["analyze"],
    summary="分析有序 allow/deny 规则的遮蔽情况",
)
def analyze(request: AnalyzeRequest) -> dict:
    """按顺序计算每条规则未被此前规则覆盖的地址集合并分类。

    非法 CIDR、IPv6、空规则集均返回 **422 Unprocessable Entity**。
    """
    # analyzer 再做一次防御性校验（该模块也可独立使用）
    try:
        return analyze_rules([(r.action, r.cidr) for r in request.rules])
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise
