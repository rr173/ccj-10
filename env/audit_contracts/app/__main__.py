"""入口：python -m app --db audit.db --port 8080"""

import argparse

from .httpapi import serve


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="audit_contracts.db")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    httpd, _ = serve(args.db, args.host, args.port)
    print(f"审计契约门禁服务监听 http://{args.host}:{args.port}  db={args.db}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


if __name__ == "__main__":
    main()
