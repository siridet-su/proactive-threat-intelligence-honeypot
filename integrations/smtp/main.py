"""
smtp-sink — accept mail and discard it without relaying or storing its body.
"""

import logging
import threading

from aiosmtpd.controller import Controller

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("smtp-sink")


class SinkHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        log.info(
            "mail received ip=%s from=%s to=%s bytes=%d (discarded, no relay)",
            session.peer[0] if session.peer else "?",
            envelope.mail_from,
            envelope.rcpt_tos,
            len(envelope.content or b""),
        )
        return "250 Message accepted for delivery"


if __name__ == "__main__":
    controller = Controller(SinkHandler(), hostname="0.0.0.0", port=25)
    controller.start()
    log.info("smtp-sink listening on :25")
    threading.Event().wait()
