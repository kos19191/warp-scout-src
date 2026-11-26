#!/usr/bin/env python3
"""
Сервер живого макета: отдаёт design/mockup и открывает его сразу в нужном дизайне.

    python3 design/serve.py                       # http://localhost:8090, «Премиум»
    python3 design/serve.py --design soft --port 8091
    python3 design/serve.py --design glass --port 8092

Дизайн можно сменить и в самом макете — панелью слева (на узком экране — полосой сверху)
или в телефоне: «Расширенный режим» → «Настройки» → «Оформление». Кэш отключён: после правки
файлов достаточно обновить страницу.
"""
import argparse
import functools
import http.server
import os

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mockup")
DESIGNS = ("premium", "soft", "glass")


class Handler(http.server.SimpleHTTPRequestHandler):
    design = None

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        if self.design and path in ("/", "/index.html"):
            with open(os.path.join(ROOT, "index.html"), "rb") as f:
                body = f.read()
            tag = ('<script>window.MOCK_DESIGN = "%s";</script>' % self.design).encode()
            body = body.replace(b"<head>", b"<head>\n" + tag, 1)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def log_message(self, fmt, *args):
        pass


def main():
    ap = argparse.ArgumentParser(description="Живой макет дизайнов WilyScout")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--design", choices=DESIGNS, default="premium")
    a = ap.parse_args()
    handler = type("DesignHandler", (Handler,), {"design": a.design})
    server = http.server.ThreadingHTTPServer((a.bind, a.port), functools.partial(handler, directory=ROOT))
    print("макет: http://%s:%d — дизайн %s" % (a.bind, a.port, a.design), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
