# -*- coding: utf-8 -*-
"""
WAPT orchestrator — thin Burp streamer (Jython, single file).

Loads into Burp with the legacy Extender API (works under Jython 2.7). It does
ONE job: every proxy request/response Burp sees, already decrypted, is POSTed to
the WAPT engine at http://127.0.0.1:8777/ingest. All triage logic lives in the
Python engine — this file is a dumb pipe you load once and forget.

------------------------------------------------------------------------------
LOAD IT (one time):
  1. Burp has Jython configured?  Extender > Options > Python Environment >
     "Location of Jython standalone JAR"  -> point at jython-standalone-2.7.x.jar
     (download once from https://www.jython.org/download if you don't have it).
  2. Extender > Extensions > Add > Extension type: Python > select this file.
  3. Start the engine:   python3 run.py --serve --lab <host> --exploit <h> --collab <h>
  4. Open the dashboard it prints (http://127.0.0.1:8777/) and browse the target.

Only IN-SCOPE traffic is streamed by default (set Burp's target scope). Flip
STREAM_IN_SCOPE_ONLY = False to stream everything. Posting is fire-and-forget on
a worker thread, so it never slows your browsing.
------------------------------------------------------------------------------
"""
from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
import threading

try:                      # Jython 2.7 ships urllib2
    import urllib2 as _url
except ImportError:
    import urllib.request as _url  # just in case

# ---- config ----------------------------------------------------------------
ENGINE = "http://127.0.0.1:8777/ingest"
STREAM_IN_SCOPE_ONLY = False   # stream all proxy traffic; the engine scope-filters on its side
STREAM_TOOLS = None        # None = proxy only; or a set of tool flags to widen
POST_TIMEOUT = 2           # seconds; fire-and-forget anyway
MAX_BODY = 400000          # don't ship enormous bodies

import json


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("WAPT orchestrator — stream")
        self._out = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)
        self._out.println("[wapt] streaming to " + ENGINE +
                          ("  (in-scope only)" if STREAM_IN_SCOPE_ONLY else "  (ALL traffic)"))

    # called for every HTTP message; we act on the response pass (have both halves)
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only proxy by default
        from burp import IBurpExtenderCallbacks as CB
        if STREAM_TOOLS is None and toolFlag != CB.TOOL_PROXY:
            return
        if messageIsRequest:
            return  # wait for the response so we have status + body
        try:
            self._handle(messageInfo)
        except Exception as e:
            self._out.println("[wapt] error: " + str(e))

    def _handle(self, messageInfo):
        svc = messageInfo.getHttpService()
        req = messageInfo.getRequest()
        resp = messageInfo.getResponse()
        reqInfo = self._helpers.analyzeRequest(svc, req)
        url = reqInfo.getUrl().toString()

        if STREAM_IN_SCOPE_ONLY and not self._cb.isInScope(reqInfo.getUrl()):
            return

        method = reqInfo.getMethod()
        req_headers = self._headers_to_dict(reqInfo.getHeaders(), skip_first=True)
        req_body = self._body(req, reqInfo.getBodyOffset())

        status = None
        resp_headers = {}
        resp_body = ""
        if resp:
            respInfo = self._helpers.analyzeResponse(resp)
            status = respInfo.getStatusCode()
            resp_headers = self._headers_to_dict(respInfo.getHeaders(), skip_first=True)
            resp_body = self._body(resp, respInfo.getBodyOffset())

        payload = {
            "method": method, "url": url,
            "req_headers": req_headers, "req_body": req_body,
            "status": status, "resp_headers": resp_headers, "resp_body": resp_body,
            "source": "burp-live",
        }
        # fire-and-forget so Burp/browsing never blocks on us
        t = threading.Thread(target=self._post, args=(payload,))
        t.setDaemon(True)
        t.start()

    def _post(self, payload):
        try:
            data = json.dumps(payload)
            req = _url.Request(ENGINE, data=data.encode("utf-8") if hasattr(data, "encode") else data,
                               headers={"Content-Type": "application/json"})
            _url.urlopen(req, timeout=POST_TIMEOUT)
        except Exception:
            pass  # engine down / busy — we just drop it, never interrupt the tester

    # ---- helpers ----
    def _headers_to_dict(self, headers, skip_first=False):
        d = {}
        hs = list(headers)
        if skip_first and hs:
            hs = hs[1:]  # drop the request/status line
        for h in hs:
            if ":" in h:
                k, v = h.split(":", 1)
                d[k.strip()] = v.strip()
        return d

    def _body(self, msg_bytes, offset):
        try:
            b = msg_bytes[offset:offset + MAX_BODY]
            return self._helpers.bytesToString(b)
        except Exception:
            return ""
