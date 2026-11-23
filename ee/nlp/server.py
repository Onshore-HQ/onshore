"""Onshore language-model service: finds names and places in text with spaCy,
Hugging Face transformers or Stanza, for Onshore's detection to add to its patterns,
checksums and name lists.

Onshore Commercial Licence (see ee/LICENSE). Runs inside the install, over mutual
TLS, with no outbound network: the model is built into the image, and text is never
written to disk or to the log.

POST /v1/entities  {"text": "..."}  ->  {"entities": [{"start", "end", "label", "score"}]}
    start and end are byte offsets into the UTF-8 text. label is "person" or "place".
GET  /healthz      ->  {"engine", "model", "ready"}

Environment:
    RV_NLP_ENGINE   spacy (default), transformers or stanza
    RV_NLP_MODEL    the model: a spaCy package, a Hugging Face model directory or ID
                    baked into the image, or a Stanza language code
    RV_TLS_CERT, RV_TLS_KEY, RV_TLS_CLIENT_CA   this service's certificate and the
                    internal CA that callers' certificates must chain to
    LISTEN_ADDR     default :8095
"""

import json
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 1 << 20

# Each engine's labels, mapped to Onshore's. Organisations aren't personal data, so
# they're left out; dates, numbers and IDs are the patterns' job.
PERSON = {"PERSON", "PER", "B-PER", "I-PER"}
PLACE = {"GPE", "LOC", "FAC", "B-LOC", "I-LOC"}

# spaCy and Stanza give no per-entity probability; this is the score they report.
FIXED_SCORE = 0.85


def label_of(raw):
    raw = (raw or "").upper()
    if raw in PERSON:
        return "person"
    if raw in PLACE:
        return "place"
    return None


class Engine:
    """Loads one engine once; find() returns (start_char, end_char, label, score)."""

    def __init__(self, engine, model):
        self.engine, self.model = engine, model
        self.lock = threading.Lock()  # models aren't all safe across threads
        if engine == "spacy":
            import spacy

            self.nlp = spacy.load(model or "en_core_web_lg", exclude=["lemmatizer", "textcat"])
        elif engine == "transformers":
            from transformers import pipeline

            self.nlp = pipeline("token-classification", model=model or "/models/hf", aggregation_strategy="simple", device=-1)
        elif engine == "stanza":
            import stanza

            self.nlp = stanza.Pipeline(model or "en", processors="tokenize,ner", download_method=None, use_gpu=False, logging_level="WARN")
        else:
            raise SystemExit(f"unknown RV_NLP_ENGINE {engine!r}: use spacy, transformers or stanza")

    def find(self, text):
        with self.lock:
            if self.engine == "spacy":
                return [(e.start_char, e.end_char, label_of(e.label_), FIXED_SCORE) for e in self.nlp(text).ents]
            if self.engine == "transformers":
                return [(e["start"], e["end"], label_of(e.get("entity_group") or e.get("entity")), float(e["score"])) for e in self.nlp(text)]
            return [(e.start_char, e.end_char, label_of(e.type), FIXED_SCORE) for e in self.nlp(text).ents]


def byte_offsets(text):
    """Character index -> UTF-8 byte offset, for Go's string indexing."""
    out, n = [0], 0
    for ch in text:
        n += len(ch.encode("utf-8"))
        out.append(n)
    return out


ENGINE = None


class Handler(BaseHTTPRequestHandler):
    server_version = "onshore-nlp"
    sys_version = ""

    def log_message(self, *args):  # request lines are noise and could carry nothing useful
        pass

    def send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            return self.send(200, {"engine": ENGINE.engine, "model": ENGINE.model, "ready": True})
        self.send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/entities":
            return self.send(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            return self.send(413, {"error": "too large"})
        try:
            text = json.loads(self.rfile.read(length)).get("text", "")
            if not isinstance(text, str):
                raise ValueError
        except (ValueError, AttributeError):
            return self.send(400, {"error": "expected {\"text\": string}"})
        try:
            found = ENGINE.find(text)
        except Exception:  # never echo the text back in an error
            print("model failed on a request", file=sys.stderr, flush=True)
            return self.send(500, {"error": "the model failed"})
        offs = byte_offsets(text)
        out = []
        for start, end, label, score in found:
            if label and 0 <= start < end <= len(text):
                out.append({"start": offs[start], "end": offs[end], "label": label, "score": round(score, 4)})
        self.send(200, {"entities": out})


def main():
    global ENGINE
    ENGINE = Engine(os.environ.get("RV_NLP_ENGINE", "spacy"), os.environ.get("RV_NLP_MODEL", ""))
    host, _, port = os.environ.get("LISTEN_ADDR", ":8095").rpartition(":")
    httpd = ThreadingHTTPServer((host or "0.0.0.0", int(port)), Handler)
    cert = os.environ.get("RV_TLS_CERT")
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(cert, os.environ["RV_TLS_KEY"])
        ca = os.environ.get("RV_TLS_CLIENT_CA")
        if ca:
            ctx.load_verify_locations(ca)
            ctx.verify_mode = ssl.CERT_REQUIRED
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"language models ready: {ENGINE.engine} {ENGINE.model or '(default)'}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
