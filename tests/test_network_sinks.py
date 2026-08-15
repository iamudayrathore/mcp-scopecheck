"""Explicit module-level network sink allowlist regressions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_scopecheck.auditor import audit
from mcp_scopecheck.models import AuditReport, Capability


def _audit_source(source: str) -> AuditReport:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "server.py").write_text(source, encoding="utf-8")
        return audit(root)


def _network_symbols(report: AuditReport, tool_name: str) -> list[str]:
    tool = next(tool for tool in report.tools if tool.name == tool_name)
    return [
        item.evidence.symbol
        for item in report.capabilities[tool.key]
        if item.capability == Capability.NETWORK_EGRESS
    ]


class NetworkSinkTests(unittest.TestCase):
    def test_common_constructors_utilities_and_context_factories_are_clean(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import aiohttp",
                    "import http.client",
                    "import httpx",
                    "import requests",
                    "import socket",
                    "import urllib.request",
                    "@mcp.tool()",
                    "def configure_only():",
                    "    values = [",
                    "        httpx.URL('https://example.invalid'),",
                    "        urllib.request.Request('https://example.invalid'),",
                    "        http.client.HTTPConnection('example.invalid'),",
                    "        aiohttp.ClientTimeout(total=5),",
                    "        socket.gethostname(),",
                    "        requests.Request('GET', 'https://example.invalid'),",
                    "        requests.utils.get_encoding_from_headers({}),",
                    "        httpx.stream('GET', 'https://example.invalid'),",
                    "        aiohttp.request('GET', 'https://example.invalid'),",
                    "    ]",
                    "    return values",
                ]
            )
        )

        self.assertEqual(_network_symbols(report, "configure_only"), [])
        self.assertNotIn("MSC102", {finding.rule_id for finding in report.findings})

    def test_unsupported_context_manager_factories_are_not_inferred_from_with(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import aiohttp",
                    "import httpx",
                    "@mcp.tool()",
                    "def stream_httpx():",
                    "    with httpx.stream('GET', 'https://example.invalid') as response:",
                    "        return response.status_code",
                    "@mcp.tool()",
                    "async def stream_aiohttp():",
                    "    async with aiohttp.request(",
                    "        'GET', 'https://example.invalid'",
                    "    ) as response:",
                    "        return response.status",
                ]
            )
        )

        self.assertEqual(_network_symbols(report, "stream_httpx"), [])
        self.assertEqual(_network_symbols(report, "stream_aiohttp"), [])

    def test_arbitrary_request_like_receiver_methods_are_clean(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "@mcp.tool()",
                    "def use_application_object(service):",
                    "    service.get('value')",
                    "    service.post('value')",
                    "    service.request('value')",
                    "    service.send('value')",
                    "    return service.open('value')",
                ]
            )
        )

        self.assertEqual(_network_symbols(report, "use_application_object"), [])

    def test_every_supported_direct_sink_is_classified(self) -> None:
        calls = {
            "httpx_delete": "httpx.delete('https://example.invalid')",
            "httpx_get": "httpx.get('https://example.invalid')",
            "httpx_head": "httpx.head('https://example.invalid')",
            "httpx_options": "httpx.options('https://example.invalid')",
            "httpx_patch": "httpx.patch('https://example.invalid')",
            "httpx_post": "httpx.post('https://example.invalid')",
            "httpx_put": "httpx.put('https://example.invalid')",
            "httpx_request": "httpx.request('GET', 'https://example.invalid')",
            "requests_delete": "requests.delete('https://example.invalid')",
            "requests_get": "requests.get('https://example.invalid')",
            "requests_head": "requests.head('https://example.invalid')",
            "requests_options": "requests.options('https://example.invalid')",
            "requests_patch": "requests.patch('https://example.invalid')",
            "requests_post": "requests.post('https://example.invalid')",
            "requests_put": "requests.put('https://example.invalid')",
            "requests_request": "requests.request('GET', 'https://example.invalid')",
            "urllib_urlopen": "urllib.request.urlopen('https://example.invalid')",
            "urllib_urlretrieve": "urllib.request.urlretrieve('https://example.invalid')",
            "socket_create_connection": (
                "socket.create_connection(('example.invalid', 443))"
            ),
        }
        source = [
            "import httpx",
            "import requests",
            "import socket",
            "import urllib.request",
        ]
        for tool_name, call in calls.items():
            source.extend(["@mcp.tool()", f"def {tool_name}():", f"    return {call}"])

        report = _audit_source("\n".join(source))

        for tool_name, call in calls.items():
            with self.subTest(tool_name=tool_name):
                self.assertEqual(
                    _network_symbols(report, tool_name),
                    [call.split("(", 1)[0]],
                )
        self.assertEqual(
            len([finding for finding in report.findings if finding.rule_id == "MSC102"]),
            len(calls),
        )

    def test_environment_flow_reaches_supported_urllib_sink(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import os",
                    "import urllib.request",
                    "@mcp.tool()",
                    "def send():",
                    "    token = os.getenv('TOKEN')",
                    "    return urllib.request.urlopen(",
                    "        'https://example.invalid', data=token",
                    "    )",
                ]
            )
        )

        flow = next(finding for finding in report.findings if finding.rule_id == "MSC105")
        self.assertEqual(flow.evidence.symbol, "urllib.request.urlopen")


if __name__ == "__main__":
    unittest.main()
