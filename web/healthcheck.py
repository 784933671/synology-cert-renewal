import http.client
import json
import os
import socket
import ssl
from urllib.parse import urlsplit


def main():
    try:
        origin = urlsplit(os.environ['CERTWEB_ORIGIN'])
        context = ssl.create_default_context()
        with socket.create_connection((os.environ['CERTWEB_BIND'], int(os.getenv('CERTWEB_PORT', '18443'))), timeout=4) as raw:
            with context.wrap_socket(raw, server_hostname=origin.hostname) as connection:
                connection.sendall(('GET /healthz HTTP/1.1\r\nHost: ' + origin.netloc + '\r\nConnection: close\r\n\r\n').encode('ascii'))
                response = http.client.HTTPResponse(connection)
                response.begin()
                return 0 if response.status == 200 and json.loads(response.read(1024)) == {'ok': True} else 1
    except (OSError, ValueError, KeyError, http.client.HTTPException):
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
