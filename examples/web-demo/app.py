"""Cruiser demo target: a "note viewer" with a path traversal vulnerability.

The flag comes from the FLAG environment variable and is written one level above the notes directory (flag.txt) at startup.
Vulnerability: /view?name= is concatenated into the path without validation, so ../flag.txt reads the flag.
"""
import os
import tempfile

from flask import Flask, abort, request

app = Flask(__name__)
DATA_DIR = tempfile.mkdtemp(prefix="cruiser_demo_")
NOTES_DIR = os.path.join(DATA_DIR, "notes")
os.makedirs(NOTES_DIR)
with open(os.path.join(NOTES_DIR, "welcome.txt"), "w", encoding="utf-8") as f:
    f.write("Welcome to the note viewer.\n")
with open(os.path.join(DATA_DIR, "flag.txt"), "w", encoding="utf-8") as f:
    f.write(os.environ.get("FLAG", "flag{not_configured}") + "\n")


@app.route("/")
def index():
    links = "".join(f'<li><a href="/view?name={n}">{n}</a></li>' for n in sorted(os.listdir(NOTES_DIR)))
    return f"<h1>Notes</h1><ul>{links}</ul>"


@app.route("/view")
def view():
    path = os.path.join(NOTES_DIR, request.args.get("name", ""))  # vulnerability: the path is not validated
    try:
        with open(path, "rb") as f:
            return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}
    except OSError:
        abort(404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
