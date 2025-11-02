"""
Gunicorn configuration for production deployment
"""

import multiprocessing
import os

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '5000')}"
workers = int(os.getenv("WEB_CONCURRENCY", multiprocessing.cpu_count() * 2 + 1))

# Worker class
worker_class = "sync"

# Timeouts
timeout = int(os.getenv("GUNICORN_TIMEOUT", "120"))
keepalive = 5

# Worker lifecycle
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "-"  # Log to stdout
errorlog = "-"  # Log to stderr
loglevel = os.getenv("LOG_LEVEL", "info")

# Process naming
proc_name = "dentistry_quiz_app"

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None
