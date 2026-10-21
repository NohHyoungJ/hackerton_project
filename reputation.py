"""Local mock of a URL reputation provider for safe UI demonstrations."""

from urllib.parse import urlsplit


class MockURLReputationService:
    """Return deterministic fixture results without contacting an external service."""

    provider_name = "로컬 모의 URL 평판 서비스"

    def check(self, raw_url):
        candidate = raw_url.strip()
        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower()
        path = parts.path or "/"

        if host == "example.com" and path.rstrip("/") == "/notice":
            return {
                "provider": self.provider_name,
                "status": "not_listed",
                "label": "모의 목록 미등록",
                "threat_types": [],
                "detail": "모의 위협 목록에 등록되지 않은 테스트 주소입니다. 실제 안전 판정은 아닙니다.",
            }

        if host == "198.51.100.23" and path.rstrip("/") == "/login":
            return {
                "provider": self.provider_name,
                "status": "listed",
                "label": "모의 피싱 기록 있음",
                "threat_types": ["SOCIAL_ENGINEERING"],
                "detail": "시연을 위해 모의 목록에 피싱 URL로 등록한 예약 테스트 주소입니다. 실제 악성 사이트가 아닙니다.",
            }

        return {
            "provider": self.provider_name,
            "status": "not_checked",
            "label": "모의 목록 확인 불가",
            "threat_types": [],
            "detail": "이 주소는 모의 위협 목록에 예시 데이터가 없습니다. 실제 평판 조회가 수행된 것은 아닙니다.",
        }
