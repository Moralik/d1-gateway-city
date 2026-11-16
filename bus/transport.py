"""HTTP-адаптер учебного брокера. Конверт и подпись остаются в bus/."""

import json
from http.client import HTTPException
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener


class Broker:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.opener = build_opener(ProxyHandler({}))

    def _request(self, path: str, payload: dict | None = None) -> dict:
        data = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8") if payload is not None else None
        request = Request(self.url + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=2) as response:
                decoded = json.load(response)
        except (HTTPException, ValueError) as exc:
            raise OSError("invalid broker response") from exc
        if not isinstance(decoded, dict):
            raise OSError("invalid broker response")
        return decoded

    def publish(self, topic: str, event: dict) -> dict:
        result = self._request("/publish", {"topic": topic, "event": event})
        if result.get("accepted") is not True or result.get("id") != event["id"]:
            raise OSError("broker did not accept the event")
        return result

    def poll(self, sub: str, topic: str | None = None) -> list[dict]:
        query = {"sub": sub}
        if topic is not None:
            query["topic"] = topic
        messages = self._request("/poll?" + urlencode(query)).get("messages")
        if not isinstance(messages, list) or any(
            not isinstance(message, dict)
            or not isinstance(message.get("topic"), str)
            or not isinstance(message.get("event"), dict)
            or not isinstance(message["event"].get("id"), str)
            for message in messages
        ):
            raise OSError("invalid broker response")
        return messages

    def ack(self, topic: str, event_id: str, sub: str) -> None:
        result = self._request("/ack", {"topic": topic, "id": event_id, "sub": sub})
        if result.get("acked") is not True:
            raise OSError("broker did not acknowledge receipt")
