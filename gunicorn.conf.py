# Gunicorn configuration file
import multiprocessing

# Workers = CPU cores × 2 + 1
workers = multiprocessing.cpu_count() * 2 + 1
# Timeout in seconds
timeout = 120
# Bind to the PORT environment variable provided by Render
bind = "0.0.0.0:$PORT"
