#!/usr/bin/env python3

import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import socketserver
import threading
import time

HOST = "0.0.0.0"
PORT = 5050

CONTROLLER_HOST = "127.0.0.1"
CONTROLLER_PORT = 5051

SESSION_SECONDS = int(os.getenv("SESSION_SECONDS", "120"))

USERS = {
    "alice": hashlib.sha256(b"alice123").hexdigest(),
    "bob": hashlib.sha256(b"bob123").hexdigest(),
}

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/auth.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

sessions = {}
sessions_lock = threading.Lock()

# Keep network access while at least one valid session exists.
active_users = set()
network_lock = threading.Lock()


def controller_request(action, username):
    """Request an access change through the OS-Ken controller."""
    request = {
        "action": action,
        "username": username,
    }

    with socket.create_connection(
        (CONTROLLER_HOST, CONTROLLER_PORT), timeout=3
    ) as conn:
        conn.settimeout(3)
        conn.sendall((json.dumps(request) + "\n").encode("utf-8"))

        with conn.makefile("rb") as response_file:
            raw = response_file.readline(4097)

    if not raw or len(raw) > 4096:
        raise RuntimeError("Invalid response from SDN controller")

    response = json.loads(raw.decode("utf-8"))

    if not response.get("ok"):
        raise RuntimeError(
            response.get("message", "Controller rejected the request")
        )

    return response


def grant_network_access(username):
    with network_lock:
        if username not in active_users:
            controller_request("grant", username)
            active_users.add(username)
            logging.info("NETWORK_ACCESS_GRANTED user=%s", username)


def revoke_network_access_if_unused(username):
    with sessions_lock:
        still_active = any(
            session["username"] == username
            and session["expires_at"] > time.time()
            for session in sessions.values()
        )

    with network_lock:
        if not still_active and username in active_users:
            controller_request("revoke", username)
            active_users.remove(username)
            logging.info("NETWORK_ACCESS_REVOKED user=%s", username)


def expire_sessions():
    while True:
        now = time.time()
        expired_users = set()

        with sessions_lock:
            for token, session in list(sessions.items()):
                if session["expires_at"] <= now:
                    expired_users.add(session["username"])
                    del sessions[token]

        for username in expired_users:
            logging.info("SESSION_EXPIRED user=%s", username)
            try:
                revoke_network_access_if_unused(username)
            except Exception:
                logging.exception(
                    "NETWORK_REVOKE_FAILED user=%s", username
                )

        time.sleep(1)


def handle_request(request):
    action = request.get("action")

    if action == "login":
        username = str(request.get("username", ""))
        password = str(request.get("password", ""))

        expected = USERS.get(username)
        supplied = hashlib.sha256(password.encode()).hexdigest()

        if expected is None or not hmac.compare_digest(
            expected, supplied
        ):
            logging.warning("LOGIN_DENIED user=%s", username[:64])
            return {"ok": False, "message": "Invalid credentials"}

        try:
            grant_network_access(username)
        except Exception:
            logging.exception(
                "NETWORK_GRANT_FAILED user=%s", username
            )
            return {
                "ok": False,
                "message": "Network access could not be granted",
            }

        token = secrets.token_urlsafe(24)
        expires_at = time.time() + SESSION_SECONDS

        with sessions_lock:
            sessions[token] = {
                "username": username,
                "expires_at": expires_at,
            }

        logging.info("LOGIN_SUCCESS user=%s", username)
        return {
            "ok": True,
            "message": "Authentication successful",
            "token": token,
            "expires_in": SESSION_SECONDS,
        }

    if action == "check":
        token = str(request.get("token", ""))

        with sessions_lock:
            session = sessions.get(token)

            if session is None:
                return {
                    "ok": False,
                    "message": "Invalid or expired session",
                }

            if session["expires_at"] <= time.time():
                username = session["username"]
                del sessions[token]
            else:
                return {
                    "ok": True,
                    "username": session["username"],
                    "expires_in": int(
                        session["expires_at"] - time.time()
                    ),
                }

        try:
            revoke_network_access_if_unused(username)
        except Exception:
            logging.exception(
                "NETWORK_REVOKE_FAILED user=%s", username
            )

        return {"ok": False, "message": "Session expired"}

    if action == "logout":
        token = str(request.get("token", ""))

        with sessions_lock:
            session = sessions.pop(token, None)

        if session is None:
            return {
                "ok": False,
                "message": "Invalid or expired session",
            }

        username = session["username"]

        try:
            revoke_network_access_if_unused(username)
        except Exception:
            logging.exception(
                "NETWORK_REVOKE_FAILED user=%s", username
            )
            return {
                "ok": False,
                "message": (
                    "Logout recorded, but network revocation failed"
                ),
            }

        logging.info("LOGOUT user=%s", username)
        return {"ok": True, "message": "Logged out"}

    return {"ok": False, "message": "Unknown action"}


class AuthHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            raw = self.rfile.readline(65537)

            if not raw or len(raw) > 65536:
                return

            request = json.loads(raw.decode("utf-8"))

            if not isinstance(request, dict):
                raise ValueError("Request must be a JSON object")

            response = handle_request(request)

        except (
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            response = {
                "ok": False,
                "message": "Invalid request",
            }
        except Exception:
            logging.exception("REQUEST_ERROR")
            response = {
                "ok": False,
                "message": "Internal server error",
            }

        self.wfile.write(
            (json.dumps(response) + "\n").encode("utf-8")
        )


class AuthServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    threading.Thread(
        target=expire_sessions, daemon=True
    ).start()

    with AuthServer((HOST, PORT), AuthHandler) as server:
        print(f"Integrated authentication server on {HOST}:{PORT}")
        print(f"Session duration: {SESSION_SECONDS} seconds")
        print("Demo users: alice / alice123, bob / bob123")
        print(
            "SDN access changes are requested through the "
            "OS-Ken controller on port 5051."
        )

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nAuthentication server stopped.")
