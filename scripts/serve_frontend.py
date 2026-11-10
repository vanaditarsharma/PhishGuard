from http.server import ThreadingHTTPServer,SimpleHTTPRequestHandler
from pathlib import Path
import os
os.chdir(Path(__file__).resolve().parents[1]/'frontend')
print('Frontend: http://127.0.0.1:8080')
ThreadingHTTPServer(('127.0.0.1',8080),SimpleHTTPRequestHandler).serve_forever()
