import importlib.util
import pathlib
import unittest


MODULE = pathlib.Path(__file__).resolve().parents[2] / "integrations" / "cowrie" / "outbound_socket_receipt.py"
spec = importlib.util.spec_from_file_location("outbound_socket_receipt", MODULE)
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)


class _Address:
    def __init__(self, host, port):
        self.host, self.port = host, port


class _Transport:
    def __init__(self, local, remote):
        self.local, self.remote = local, remote

    def getHost(self):
        return _Address(*self.local)

    def getPeer(self):
        return _Address(*self.remote)


class _Protocol:
    def __init__(self, local, remote):
        self.transport = _Transport(local, remote)


class _Deferred:
    def __init__(self, result):
        self.result = result

    def addCallback(self, callback):
        self.result = callback(self.result)
        return self


class _Endpoint:
    def __init__(self, protocol):
        self.protocol = protocol

    def connect(self, factory):
        return _Deferred(self.protocol)


class CowrieOutboundReceiptTests(unittest.TestCase):
    def test_records_exact_socket_for_each_session(self):
        seen_a, seen_b = [], []
        a = _Protocol(("192.168.89.112", 54001), ("93.184.215.14", 80))
        b = _Protocol(("192.168.89.112", 54002), ("93.184.215.14", 80))
        self.assertIs(receipt.RecordingEndpoint(_Endpoint(a), seen_a.append).connect(None).result, a)
        self.assertIs(receipt.RecordingEndpoint(_Endpoint(b), seen_b.append).connect(None).result, b)
        self.assertEqual(seen_a[0]["outbound_src_port"], 54001)
        self.assertEqual(seen_b[0]["outbound_src_port"], 54002)
        self.assertNotEqual(seen_a, seen_b)

    def test_invalid_or_missing_socket_is_not_recorded(self):
        seen = []
        for protocol in (object(), _Protocol(("::1", 54001), ("93.184.215.14", 80)),
                         _Protocol(("192.168.89.112", 0), ("93.184.215.14", 80))):
            receipt.RecordingEndpoint(_Endpoint(protocol), seen.append).connect(None)
        self.assertEqual(seen, [])

    def test_telemetry_failure_does_not_break_http_connection(self):
        protocol = _Protocol(("192.168.89.112", 54001), ("93.184.215.14", 80))

        def fail(_):
            raise RuntimeError("telemetry unavailable")

        self.assertIs(receipt.RecordingEndpoint(_Endpoint(protocol), fail).connect(None).result, protocol)


if __name__ == "__main__":
    unittest.main()
