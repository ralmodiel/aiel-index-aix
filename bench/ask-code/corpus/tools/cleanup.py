import os, time

def delete_old_logs(folder, days):
    """Delete log files in a folder that were not modified for the given number of days."""
    cutoff = time.time() - days * 86400
    removed = 0
    for name in os.listdir(folder):
        p = os.path.join(folder, name)
        if name.endswith(".log") and os.path.getmtime(p) < cutoff:
            os.remove(p)
            removed += 1
    return removed
