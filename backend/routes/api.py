"""REST API. Passwords are processed transiently: never logged, stored, or echoed back (even in errors)."""
from flask import Blueprint, current_app, jsonify, request
from backend.services.password_analyzer import analyze_password, PasswordTooLongError
from backend.services.password_generator import generate_password, generate_passphrase

api = Blueprint("api", __name__, url_prefix="/api")


def _err(status, message):
    return jsonify({"error": message}), status        # fixed messages only; never include user input


@api.before_request
def _rate_limit():
    if not current_app.config["LIMITER"].allow(request.remote_addr or "unknown"):
        return _err(429, "Too many requests. Please slow down.")


@api.post("/analyze")
def analyze():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or "password" not in data:
        return _err(400, "Request body must be JSON containing a 'password' field.")
    ctx = data.get("context") if isinstance(data.get("context"), dict) else None
    pol = data.get("policy") if isinstance(data.get("policy"), dict) else None
    try:
        result = analyze_password(data["password"], ctx, pol)
    except PasswordTooLongError:
        return _err(422, "Password is longer than the maximum supported length.")
    except ValueError:
        return _err(422, "Invalid input.")
    # Only record when explicitly requested (never on every keystroke) and only metadata.
    store = current_app.config.get("STORE")
    if data.get("record") is True and store:
        store.record(result)
    return jsonify(result)                            # contains no password


@api.get("/dashboard/stats")
def stats():
    store = current_app.config.get("STORE")
    return jsonify(store.stats()) if store else _err(404, "Analytics disabled.")


@api.get("/analytics/weaknesses")
def weaknesses():
    store = current_app.config.get("STORE")
    return jsonify(store.weaknesses()) if store else _err(404, "Analytics disabled.")


@api.post("/generate-password")
def generate():
    data = request.get_json(silent=True) or {}
    try:
        if data.get("mode") == "passphrase":
            phrase, bits = generate_passphrase(int(data.get("words", 5)))
            return jsonify({"password": phrase, "type": "passphrase", "estimated_bits": bits,
                            "note": "Demo word list: use a 7,776-word list for real passphrases."})
        pw = generate_password(int(data.get("length", 20)), bool(data.get("uppercase", True)),
                               bool(data.get("lowercase", True)), bool(data.get("numbers", True)),
                               bool(data.get("symbols", True)))
        return jsonify({"password": pw, "type": "password"})
    except (ValueError, TypeError):
        return _err(422, "Invalid generator options.")


@api.get("/health")
def health():
    return jsonify({"status": "ok"})
