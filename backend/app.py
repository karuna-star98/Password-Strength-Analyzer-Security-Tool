"""Flask application factory.  Run:  python -m backend.app"""
import os
from flask import Flask, jsonify, send_from_directory
from backend import config
from backend.models.analytics import AnalyticsStore
from backend.routes.api import api
from backend.utils.rate_limit import RateLimiter


def create_app(test_config=None):
    app = Flask(__name__, static_folder=str(config.FRONTEND_DIR), static_url_path="")
    app.config.update(MAX_CONTENT_LENGTH=config.MAX_REQUEST_BYTES, LIMITER=RateLimiter(config.RATE_LIMIT_PER_MIN))
    app.config["STORE"] = AnalyticsStore(config.ANALYTICS_DB) if config.ANALYTICS_ENABLED else None
    if test_config:
        app.config.update(test_config)
    app.register_blueprint(api)

    @app.get("/")
    def index():
        return send_from_directory(config.FRONTEND_DIR, "index.html")

    @app.after_request
    def security_headers(resp):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; "
                                                   "connect-src 'self'; frame-ancestors 'none'")
        return resp

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({"error": "Request too large."}), 413

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "Not found."}), 404

    @app.errorhandler(Exception)
    def internal(_):                                   # generic: tracebacks could contain request data
        return jsonify({"error": "Internal server error."}), 500

    return app


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    create_app().run(host="0.0.0.0", port=port, debug=False)
