from flask import Flask, render_template, request
from datetime import datetime, timezone
from pathlib import Path

app = Flask(__name__)

LOG_FILE = Path("visits.log")


@app.route("/")
def home():
    visitor_ip = request.remote_addr
    timestamp = datetime.now(timezone.utc).isoformat()

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(f"{timestamp}\t{visitor_ip}\n")

    return render_template("index.html")


if __name__ == "__main__":
    app.run(host='0.0.0.0',port=5000,debug=True)