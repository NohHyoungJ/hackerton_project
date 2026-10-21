import json
import ipaddress
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from reputation import MockURLReputationService


ROOT = Path(__file__).parent
PAGE = (ROOT / "static" / "index.html").read_bytes()
MAX_MESSAGE_LENGTH = 5000
URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"'…]+", re.IGNORECASE)
TRAILING_URL_PUNCTUATION = ".,!?;:)]}，。！？；：」』”’"
SUSPICIOUS_PATTERNS = [
    ("긴급·압박", re.compile(r"즉시|긴급|\d+분\s*(?:후|내)|오늘까지|곧\s*정지|기한\s*내")),
    ("계정·인증", re.compile(r"계정\s*(?:정지|잠금|차단)|본인\s*인증|인증번호|비밀번호|로그인|보안\s*확인")),
    ("금전 요구", re.compile(r"결제|송금|입금|수수료|환급|환불|미납|연체|과태료|벌금|대출")),
    ("링크 유도", re.compile(r"링크|주소를\s*눌러|접속|클릭|확인해\s*주세요|신청하기")),
    ("앱 설치 유도", re.compile(r"앱\s*설치|어플\s*설치|보안\s*프로그램|원격\s*제어")),
]
INSTITUTION_CANDIDATES = [
    "국세청", "경찰청", "검찰청", "법원", "우체국", "국민건강보험공단",
    "정부24", "카카오", "국민은행", "신한은행", "우리은행", "하나은행",
    "농협", "택배", "카드사",
]
OFFICIAL_DOMAINS = {
    "국세청": ("nts.go.kr",),
    "경찰청": ("police.go.kr",),
    "국민건강보험공단": ("nhis.or.kr",),
    "정부24": ("gov.kr",),
}
URL_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly", "buff.ly"}


class IntakeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def do_POST(self):
        if self.path not in ("/submit", "/api/submit"):
            self.send_error(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if length > 30000:
            self.send_error(413)
            return

        form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        message = form.get("message", [""])[0].strip()
        if not message:
            self.respond("문자 내용을 입력해 주세요.", 400)
            return
        if len(message) > MAX_MESSAGE_LENGTH:
            self.respond("문자 내용은 5,000자 이내로 입력해 주세요.", 400)
            return

        # Stage 2 and 3 run in memory. The submitted text is never persisted.
        result = self.extract_details(message)
        mock_reputation = MockURLReputationService()
        result["reputation"] = [
            {"url": item["original"], **mock_reputation.check(item["original"])}
            for item in result["urls"]
        ]
        result["risk_analysis"] = self.analyze_risk(message, result)
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        payload = json.dumps(result, ensure_ascii=False).encode("utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    @staticmethod
    def extract_details(message):
        urls = []
        for match in URL_PATTERN.finditer(message):
            raw = match.group(0).rstrip(TRAILING_URL_PUNCTUATION)
            candidate = raw if raw.lower().startswith(("http://", "https://")) else f"http://{raw}"
            parts = urlsplit(candidate)
            host = (parts.hostname or "").lower()
            if not host:
                continue
            if host == "example.com" or host.endswith(".example.com"):
                note = "문서용 예약 도메인 예시"
            elif host.startswith("198.51.100."):
                note = "문서용 TEST-NET-2 예약 IP 예시"
            elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                note = "IP 주소 형태의 URL"
            elif parts.scheme.lower() == "http":
                note = "암호화되지 않은 HTTP 주소"
            else:
                note = "추가 확인이 필요한 URL 후보"
            urls.append({
                "original": raw,
                "scheme": parts.scheme.lower(),
                "domain": host,
                "path": parts.path or "/",
                "note": note,
            })

        institutions = [name for name in INSTITUTION_CANDIDATES if name in message]
        indicators = []
        for category, pattern in SUSPICIOUS_PATTERNS:
            for match in pattern.finditer(message):
                phrase = match.group(0).strip()
                if phrase and {"category": category, "phrase": phrase} not in indicators:
                    indicators.append({"category": category, "phrase": phrase})
        phones = list(dict.fromkeys(re.findall(r"(?<!\d)(?:\+82[- ]?)?(?:0\d{1,2})[- ]?\d{3,4}[- ]?\d{4}(?!\d)", message)))

        return {
            "status": "접수 완료",
            "message": "위험 징후 분석이 완료되었습니다. 규칙 기반 참고 결과이며 확정 판정은 아닙니다.",
            "urls": urls,
            "institutions": institutions,
            "phones": phones,
            "indicators": indicators,
        }

    @staticmethod
    def analyze_risk(message, details):
        score = 0
        evidence = []
        score_factors = []
        doc_urls = []
        normal_urls = []
        for item in details["urls"]:
            host = item["domain"]
            if host == "example.com" or host.endswith(".example.com"):
                doc_urls.append("example.com (문서용 예약 도메인)")
                continue
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False
            if is_ip and host.startswith("198.51.100."):
                doc_urls.append(f"{host} (TEST-NET-2 문서용 예약 IP)")
                continue

            normal_urls.append(item)
            if is_ip:
                score += 3
                score_factors.append({"points": 3, "reason": "URL이 도메인 이름 대신 숫자 IP 주소를 사용"})
                evidence.append(f"URL 호스트가 도메인 이름이 아닌 IP 주소입니다: {host}")
            if item["scheme"] == "http":
                score += 2
                score_factors.append({"points": 2, "reason": "암호화되지 않은 HTTP 링크"})
                evidence.append(f"URL이 암호화 연결을 보장하지 않는 HTTP로 시작합니다: {host}")
            if "xn--" in host:
                score += 2
                score_factors.append({"points": 2, "reason": "주소에 변환된 국제화 도메인 표기가 포함"})
                evidence.append(f"도메인에 국제화 도메인 인코딩(xn--)이 포함되어 있어 원문 확인이 필요합니다: {host}")
            if host in URL_SHORTENERS:
                score += 1
                score_factors.append({"points": 1, "reason": "실제 주소를 숨길 수 있는 단축 링크"})
                evidence.append(f"목적 도메인을 가리는 URL 단축 서비스 주소입니다: {host}")

        for reputation in details["reputation"]:
            if reputation["status"] == "listed":
                score += 5
                score_factors.append({"points": 5, "reason": "로컬 모의 평판 목록에 위험 기록이 있음 (시연 전용)"})
                evidence.append("모의 URL 평판 서비스의 테스트 목록에서 위협 기록이 발견되었습니다: " + ", ".join(reputation["threat_types"]))
            elif reputation["status"] == "not_listed":
                evidence.append("모의 URL 평판 목록에서 기록을 찾지 못했습니다. 실제 안전 판정은 아닙니다")
            else:
                evidence.append("이 URL은 모의 평판 목록에 등록된 테스트 데이터가 없어 결과를 확인할 수 없습니다")

        matched_official_claims = [name for name in details["institutions"] if name in OFFICIAL_DOMAINS]
        for name in matched_official_claims:
            expected_domains = OFFICIAL_DOMAINS[name]
            if not normal_urls:
                continue
            matched = any(
                any(item["domain"] == domain or item["domain"].endswith("." + domain) for domain in expected_domains)
                for item in normal_urls
            )
            if not matched:
                score += 2
                score_factors.append({"points": 2, "reason": f"본문의 {name} 언급과 확인된 공식 도메인이 불일치"})
                evidence.append(f"본문에는 {name}이(가) 나오지만 URL은 확인된 공식 도메인({', '.join(expected_domains)})과 일치하지 않습니다")

        indicator_categories = {item["category"] for item in details["indicators"]}
        for category, weight, explanation in [
            ("긴급·압박", 1, "시간 압박이나 긴급 행동을 요구하는 표현이 있습니다"),
            ("계정·인증", 2, "계정·로그인·인증 정보를 요구하거나 계정 문제를 언급합니다"),
            ("금전 요구", 2, "결제·송금·환급 등 금전 관련 표현이 있습니다"),
            ("앱 설치 유도", 2, "앱 설치나 원격 제어를 유도하는 표현이 있습니다"),
        ]:
            if category in indicator_categories:
                score += weight
                score_factors.append({"points": weight, "reason": explanation})
                evidence.append(explanation)

        if normal_urls and "긴급·압박" in indicator_categories and indicator_categories.intersection({"계정·인증", "금전 요구", "앱 설치 유도"}):
            score += 2
            score_factors.append({"points": 2, "reason": "URL과 긴급 압박 및 계정·금전 요구가 함께 나타남"})
            evidence.append("URL과 함께 긴급 압박 및 계정·금전 관련 표현이 결합되어 있습니다")

        if score >= 5:
            level = "high"
            label = "위험 징후 다수"
            summary = "서로 다른 위험 단서가 함께 발견되었습니다. 링크를 열거나 정보를 입력하지 말고 공식 경로로 확인하세요."
        elif score >= 2:
            level = "medium"
            label = "주의가 필요한 징후"
            summary = "확인이 필요한 단서가 발견되었습니다. 자동 분석만으로 피싱 여부를 확정할 수 없습니다."
        else:
            level = "low"
            label = "뚜렷한 자동 감지 징후 없음"
            summary = "현재 규칙에서 강한 위험 징후가 적게 발견되었습니다. 안전하다는 뜻은 아니므로 발신자와 요청을 별도로 확인하세요."

        if doc_urls:
            evidence.append("문서·테스트용으로 예약된 주소는 위험 점수에서 제외했습니다: " + ", ".join(doc_urls))
        if not evidence:
            evidence.append("현재 적용한 규칙에서 강한 위험 징후를 찾지 못했습니다")

        public_reasons = []
        if any(item["status"] == "listed" for item in details["reputation"]):
            public_reasons.append("URL 평판 목록에서 위험 기록을 찾았습니다 (모의 시연 데이터)")
        for name in matched_official_claims:
            expected_domains = OFFICIAL_DOMAINS[name]
            if normal_urls and not any(
                any(item["domain"] == domain or item["domain"].endswith("." + domain) for domain in expected_domains)
                for item in normal_urls
            ):
                public_reasons.append(f"문자에 적힌 {name}의 공식 주소와 링크가 일치하지 않습니다")
        simple_reasons = [
            ("긴급·압박", "시간을 재촉해 행동을 서두르게 합니다"),
            ("계정·인증", "계정이나 본인 인증 정보를 입력하도록 유도합니다"),
            ("금전 요구", "결제·송금 등 금전 처리를 요구합니다"),
            ("앱 설치 유도", "앱 설치나 원격 제어를 안내합니다"),
        ]
        for category, reason in simple_reasons:
            if category in indicator_categories and reason not in public_reasons:
                public_reasons.append(reason)
        if any(item["scheme"] == "http" for item in normal_urls):
            public_reasons.append("보안 연결(HTTPS)이 아닌 링크를 사용합니다")
        if any(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", item["domain"]) for item in normal_urls):
            public_reasons.append("기관 도메인 대신 숫자 주소(IP)를 사용합니다")
        if any(item["domain"] in URL_SHORTENERS for item in normal_urls):
            public_reasons.append("실제 사이트 주소를 바로 알기 어려운 단축 링크입니다")
        if not public_reasons:
            public_reasons.append("현재 규칙에서 뚜렷한 위험 신호를 찾지 못했습니다")

        public_verdict = {"high": "의심", "medium": "확인 필요", "low": "뚜렷한 위험 신호 없음"}[level]
        if level == "low":
            recommended_action = "위험 신호가 적어도 안전하다는 뜻은 아닙니다. 링크 대신 기관의 공식 앱이나 대표번호를 직접 찾아 확인하세요."
        else:
            recommended_action = "문자 링크는 누르지 말고 기관의 공식 앱이나 대표번호로 확인하세요. 인증번호·비밀번호·결제정보도 입력하지 마세요."

        if level == "high":
            decision_explanation = f"확인된 단서 점수가 {score}점으로, 5점 이상인 ‘의심’ 구간입니다. 아래 항목별 점수를 확인해 주세요."
        elif level == "medium":
            decision_explanation = f"확인된 단서 점수가 {score}점으로, 2~4점인 ‘확인 필요’ 구간입니다. 한 가지 단서만으로 피싱을 확정하지 않습니다."
        else:
            decision_explanation = "확인된 단서 점수가 0~1점 구간입니다. 자동 규칙에서 뚜렷한 단서를 적게 찾았다는 뜻이며, 안전 판정은 아닙니다."

        return {
            "level": level,
            "label": label,
            "summary": summary,
            "public_verdict": public_verdict,
            "public_reasons": public_reasons[:4],
            "recommended_action": recommended_action,
            "decision_explanation": decision_explanation,
            "score_factors": score_factors,
            "score": score,
            "evidence": evidence,
            "method": "본문·URL 로컬 규칙 + 로컬 모의 URL 평판 서비스",
            "limitations": [
                "URL 평판 응답은 시연용 모의 데이터이며 실제 외부 서비스 응답이 아닙니다",
                "문자와 URL은 저장하거나 외부 서비스로 전송하지 않습니다",
                "공식 도메인 대조는 일부 기관만 포함합니다. 목록이 불완전하거나 갱신되지 않으면 오탐이 생길 수 있습니다",
                "분석 규칙에 없거나 새로 만들어진 사칭 방식은 놓칠 수 있습니다",
                "점수와 결과는 보안 판정이나 기관의 진위 확인을 대신하지 않습니다",
            ],
        }

    def respond(self, message, status=400):
        payload = json.dumps({"error": message}, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        # Avoid writing request details to the terminal while handling message intake.
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8000), IntakeHandler)
    print("문자 접수 화면: http://127.0.0.1:8000")
    print("개발용 접수 서버입니다. 입력 문자는 저장하지 않습니다. Ctrl+C로 종료하세요.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n서버를 종료했습니다.")
    finally:
        server.server_close()
