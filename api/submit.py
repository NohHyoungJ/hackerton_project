import json
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import IntakeHandler, MAX_MESSAGE_LENGTH  # noqa: E402
from reputation import MockURLReputationService  # noqa: E402


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.respond({"error": "요청 내용을 읽을 수 없습니다."}, 400)
            return
        if length > 30000:
            self.respond({"error": "요청 크기가 너무 큽니다."}, 413)
            return

        form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        message = form.get("message", [""])[0].strip()
        if not message:
            self.respond({"error": "문자 내용을 입력해 주세요."}, 400)
            return
        if len(message) > MAX_MESSAGE_LENGTH:
            self.respond({"error": "문자 내용은 5,000자 이내로 입력해 주세요."}, 400)
            return

        result = IntakeHandler.extract_details(message)
        reputation = MockURLReputationService()
        result["reputation"] = [
            {"url": item["original"], **reputation.check(item["original"])}
            for item in result["urls"]
        ]
        result["risk_analysis"] = IntakeHandler.analyze_risk(message, result)
        self.respond(result, 200)

    def respond(self, data, status):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return
