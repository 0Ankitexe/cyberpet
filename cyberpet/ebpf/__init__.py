"""CyberPet V2 eBPF-based kernel monitors.

This package contains:
- exec_monitor: eBPF-based process execution monitoring
- file_monitor: fanotify-based file access monitoring

Both monitors require root privileges and degrade gracefully
when unavailable.
"""
