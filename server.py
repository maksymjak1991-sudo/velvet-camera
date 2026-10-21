"""Velvet Telegram Mini App video upload server.

Deploy as a Render Web Service with:
  pip install -r requirements.txt
  gunicorn server:app --bind 0.0.0.0:$PORT --timeout 120

Set BOT_TOKEN and MINIAPP_ORIGIN in Render environment variables.
Never commit the bot token to GitHub.
"""

import hashlib
import hmac
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qsl

import imageio_ffmpeg
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
app.logger.warning("Token fingerprint: %s", hashlib.sha256(BOT_TOKEN.encode()).hexdigest()[:12])
MINIAPP_ORIGIN = os.environ.get("MINIAPP_ORIGIN", "").rstrip("/")
MAX_AGE_SECONDS = 60 * 60


@app.after_request
def add_cors_headers(response):
    # CORS is a browser feature, not authentication; initData is verified below.
    origin = request.headers.get("Origin", "")
    if MINIAPP_ORIGIN and origin == MINIAPP_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = MINIAPP_ORIGIN
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
    return response


@app.get("/health")
def health():
    return jsonify(status="ok")


def verify_telegram_data(init_data):
    """Return Telegram user id only for authentic, fresh Mini App initData."""
    if not BOT_TOKEN or not init_data or len(init_data) > 8192:
        return None

    try:
        pairs = parse_qsl(init_data, keep_blank_values=True, strict_parsing=True)
        data = dict(pairs)
        if len(pairs) != len(data):
            return None
        received_hash = data.pop("hash", "")
        data.pop("signature", None)
        app.logger.warning("Telegram initData fields: %s", sorted(data.keys()))
        if len(received_hash) != 64:
            return None


        check_string = "\n".join(f"{key}={value}" for key, value in sorted(data.items()))
        secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        expected_hash = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_hash, received_hash):
            app.logger.warning("Telegram authentication failed: hash mismatch")

            return None

        auth_date = int(data["auth_date"])
        now = int(time.time())
        if auth_date > now + 60 or now - auth_date > MAX_AGE_SECONDS:
            return None 

        user = json.loads(data["user"])
        user_id = int(user["id"])
        if user_id <= 0:
            return None
        return user_id
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


@app.route("/upload", methods=["POST", "OPTIONS"])
def upload():
    if request.method == "OPTIONS":
        return ("", 204)

    # Require the expected website origin in addition to Telegram authentication.
    if not MINIAPP_ORIGIN or request.headers.get("Origin") != MINIAPP_ORIGIN:
        return jsonify(error="Origin not allowed"), 403
    if not BOT_TOKEN:
        return jsonify(error="Server is not configured"), 503

    user_id = verify_telegram_data(request.form.get("init_data", ""))
 
    if user_id is None:
        return jsonify(error="Open Velvet from Telegram and try again"), 401

    uploaded = request.files.get("video")
    if not uploaded or not uploaded.filename:
        return jsonify(error="Video file missing"), 400

    try:
        with tempfile.TemporaryDirectory(prefix="velvet_") as tmp:
            source = Path(tmp) / "source.webm"
            output = Path(tmp) / "video_note.mp4"
            uploaded.save(source)
            if source.stat().st_size == 0:
                return jsonify(error="Empty video"), 400

            command = [
                imageio_ffmpeg.get_ffmpeg_exe(),
                "-hide_banner", "-loglevel", "error", "-y",
                "-i", str(source),
                "-t", "60", "-an",
                "-vf", "scale=480:480:force_original_aspect_ratio=increase,crop=480:480,fps=25",
                "-c:v", "libx264", "-preset", "veryfast", "-crf", "28",
                "-pix_fmt", "yuv420p", "-movflags", "+faststart",
                str(output),
            ]
            subprocess.run(command, check=True, timeout=100, capture_output=True)

            with output.open("rb") as video_file:
                response = requests.post(
                    f"https://api.telegram.org/bot{BOT_TOKEN}/sendVideoNote",
                    data={"chat_id": user_id, "length": 480},
                    files={"video_note": ("video_note.mp4", video_file, "video/mp4")},
                    timeout=60,
                )
            telegram_response = response.json()
            if not response.ok or not telegram_response.get("ok"):
                app.logger.warning("Telegram sendVideoNote failed: %s", telegram_response.get("description", "unknown"))
                return jsonify(error="Telegram could not deliver the video. Start the bot and retry."), 502
            return jsonify(ok=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        app.logger.exception("Video conversion failed")
        return jsonify(error="Could not process video"), 422
    except (requests.RequestException, ValueError, OSError):
        app.logger.exception("Video upload failed")
        return jsonify(error="Video delivery failed"), 502


@app.errorhandler(413)
def too_large(_error):
    return jsonify(error="Video is too large (20 MB maximum)"), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
