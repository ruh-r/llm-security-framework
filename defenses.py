"""
defenses.py — Project AEGIS 다층 방어 엔진

Layer 1: RuleBasedGuardrail
  - 정규식 기반 패턴 시그니처로 프롬프트 인젝션의 '형태'를 탐지한다.
  - 목표: ATTACK_CORPUS recall↑ 를 유지하면서 BENIGN_CORPUS 오탐↓.
  - 설계: 단순 키워드 포함이 아니라 (a) 패턴 클래스별 시그니처,
          (b) 무해한 용례를 살려주는 negative guard 를 함께 둔다.
"""

import re
from dataclasses import dataclass, field
from enum import Enum


class Verdict(Enum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass
class DetectionResult:
    verdict: Verdict
    score: float                       # 0.0 ~ 1.0, 누적 위험도
    matched: list = field(default_factory=list)  # (규칙명, 근거 텍스트)

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK


@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    weight: float          # 이 규칙이 맞으면 더해지는 위험 점수
    description: str


class RuleBasedGuardrail:
    """
    각 규칙은 '패턴 클래스의 시그니처'를 노린다.
    누적 점수가 threshold 이상이면 BLOCK.
    점수제를 쓰는 이유: 단일 키워드 1건으로 단정하지 않고,
    여러 약한 신호가 겹칠 때 신뢰도를 올리기 위함.
    """

    def __init__(self, threshold: float = 1.0):
        self.threshold = threshold
        self.rules = self._build_rules()
        # 무해한 문맥을 살려주는 가드. 매칭되면 해당 신호를 감쇄한다.
        self.benign_guards = [
            # "ignore the typo in my previous message" 류: 교정 요청
            re.compile(r"ignore\s+(the\s+)?(typo|error|mistake|whitespace)", re.I),
            # "how does a system prompt work" 류: 개념 질문
            re.compile(r"(how|what|why)\b.{0,40}\b(system prompt|prompt injection)\b.{0,40}\b(work|mean|is)\b", re.I),
        ]

    def _build_rules(self):
        return [
            Rule(
                "direct_override",
                re.compile(r"\bignore\b.{0,30}\b(all\s+)?(previous|prior|above|earlier)\b.{0,30}\b(instruction|rule|prompt|direction)", re.I),
                weight=1.0,
                description="명령형 + previous/above + instructions 결합: 직접 지시 무시",
            ),
            Rule(
                "roleplay_norules",
                re.compile(r"\byou\s+are\b.{0,40}\b(no\s+rules|no\s+restrictions|unrestricted|jailbroken|DAN|freebot)\b", re.I),
                weight=1.0,
                description="규칙 없는 페르소나 부여: 역할극 우회",
            ),
            Rule(
                "fiction_frame",
                re.compile(r"\b(for\s+a\s+)?(fiction|novel|story|hypothetical|roleplay)\b.{0,60}\b(no\s+restrictions|would\s+say|without\s+rules)\b", re.I),
                weight=0.7,
                description="허구 프레임으로 책임 외부화",
            ),
            Rule(
                "env_simulation",
                re.compile(r"\byou\s+are\s+(now\s+)?(a\s+)?(linux\s+)?terminal\b|\brespond\s+only\s+with\s+(command\s+)?output\b|^\s*\$\s*\w+", re.I | re.M),
                weight=1.0,
                description="가상 터미널/환경 유도로 응답 형식 강제",
            ),
            Rule(
                "context_gaslighting",
                re.compile(r"\byou\s+(already|previously)\s+(agreed|promised|said|confirmed)\b|\bremember\?\s*$", re.I),
                weight=0.8,
                description="존재하지 않는 과거 합의 단정: 맥락 조작",
            ),
            Rule(
                "multi_step",
                re.compile(r"\b(first|step\s*1)\b.{0,80}\b(then|next|finally|step\s*2)\b.{0,80}\b(ignore|output|reveal|bypass|disable)\b", re.I | re.S),
                weight=0.9,
                description="단계 분할 점진적 유도",
            ),
            Rule(
                "encoding_obfuscation",
                re.compile(r"\b(base64|rot13|hex|decode)\b.{0,40}\b(follow|execute|run|then\s+do)\b|[A-Za-z0-9+/]{16,}={0,2}", re.I),
                weight=0.7,
                description="인코딩으로 지시 은닉",
            ),
            Rule(
                "system_leak",
                re.compile(r"\b(repeat|print|show|reveal|output)\b.{0,30}\b(the\s+)?(text\s+above|system\s+prompt|your\s+instructions|configuration|secret|codename)\b", re.I),
                weight=1.0,
                description="시스템 프롬프트/비밀 추출 시도",
            ),
            Rule(
                "verbatim_echo",
                re.compile(r"\b(verbatim|word\s*for\s*word)\b|\bstarting\s+with\s+['\"]you\s+are['\"]", re.I),
                weight=0.6,
                description="원문 그대로 토해내기 유도",
            ),
        ]

    def inspect(self, text: str) -> DetectionResult:
        score = 0.0
        matched = []

        for rule in self.rules:
            m = rule.pattern.search(text)
            if m:
                score += rule.weight
                matched.append((rule.name, m.group(0)[:60]))

        # negative guard: 무해 문맥이면 위험도 감쇄
        for guard in self.benign_guards:
            if guard.search(text):
                score -= 0.8
                matched.append(("benign_guard", guard.search(text).group(0)[:60]))

        score = max(0.0, score)
        verdict = Verdict.BLOCK if score >= self.threshold else Verdict.ALLOW
        return DetectionResult(verdict=verdict, score=round(score, 2), matched=matched)


if __name__ == "__main__":
    # 빠른 자가 점검 (정식 평가는 별도 하니스에서)
    from payloads import ATTACK_CORPUS, BENIGN_CORPUS

    guard = RuleBasedGuardrail(threshold=1.0)

    print("=== ATTACK_CORPUS (기대: BLOCK) ===")
    for p in ATTACK_CORPUS:
        r = guard.inspect(p.text)
        flag = "✓" if r.blocked else "✗ MISS"
        print(f"[{flag}] score={r.score:<4} {p.attack_class.value:18} | {p.text[:50]}")

    print("\n=== BENIGN_CORPUS (기대: ALLOW) ===")
    for p in BENIGN_CORPUS:
        r = guard.inspect(p.text)
        flag = "✓" if not r.blocked else "✗ FALSE POSITIVE"
        print(f"[{flag}] score={r.score:<4} | {p.text[:50]}")