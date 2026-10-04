from flask import Flask, render_template, request
from datetime import datetime, timezone
from pathlib import Path

app = Flask(__name__)

LOG_FILE = Path("visits.log")


@app.route("/")
def home():

    direct_ip = request.remote_addr

  
    forwarded_for = request.headers.get("X-Forwarded-For")

    if forwarded_for:
        visitor_ip = forwarded_for.split(",")[0].strip()
    else:
        visitor_ip = direct_ip

    timestamp = datetime.now(timezone.utc).isoformat()

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(
            f"{timestamp}\t"
            f"visitor={visitor_ip}\t"
            f"direct={direct_ip}\t"
            f"forwarded={forwarded_for}\n"
        )

    print(
        f"{timestamp} | "
        f"visitor={visitor_ip} | "
        f"direct={direct_ip} | "
        f"forwarded={forwarded_for}",
        flush=True
    )

    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)