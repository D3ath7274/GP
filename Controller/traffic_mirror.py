"""
Traffic Mirror for SDN Controller + Snort IDS
==============================================
Creates a TAP interface and injects mirrored packets from OpenFlow packet_in
events so Snort can analyze all data-plane traffic (including 10.0.0.x from
Mininet) on the controller machine.

Requires: Linux, root/sudo, /dev/net/tun
"""

import os
import struct
import fcntl
import queue
import threading
import subprocess

# Linux TUN/TAP ioctl constants
TUNSETIFF = 0x400454ca
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

DEFAULT_TAP_NAME = 'snort_tap'
MAX_QUEUE_SIZE = 50000
WRITER_SLEEP = 0.001


class TrafficMirror:
    """
    Creates a TAP interface and injects raw Ethernet frames into it.
    Packets arrive via inject() and are written by a background thread.
    Snort captures on this TAP to analyze mirrored traffic.
    """

    def __init__(self, tap_name=DEFAULT_TAP_NAME, max_queue_size=MAX_QUEUE_SIZE,
                 logger=None):
        self.tap_name = tap_name
        self.max_queue_size = max_queue_size
        self.logger = logger
        self._tap_fd = None
        self._queue = queue.Queue(maxsize=max_queue_size)
        self._writer_thread = None
        self._running = False
        self._packets_injected = 0
        self._packets_dropped = 0

    def _log(self, level, msg, *args):
        if self.logger:
            getattr(self.logger, level)(msg, *args)
        else:
            print(f"[TrafficMirror] {msg % args if args else msg}")

    def start(self):
        """Create TAP interface and start the writer thread."""
        if self._running:
            return True

        try:
            self._tap_fd = os.open('/dev/net/tun', os.O_RDWR)
        except (OSError, FileNotFoundError) as e:
            self._log('error', "Cannot open /dev/net/tun: %s. Run with sudo.", str(e))
            return False

        try:
            # ifreq: 16 bytes name + 2 bytes flags + padding to 40 bytes (64-bit Linux)
            name_bytes = self.tap_name.encode()[:15].ljust(16, b'\x00')[:16]
            ifr = struct.pack('16sH22x', name_bytes, IFF_TAP | IFF_NO_PI)
            fcntl.ioctl(self._tap_fd, TUNSETIFF, ifr)
        except OSError as e:
            os.close(self._tap_fd)
            self._tap_fd = None
            # Non-fatal: controller falls back to physical interface only
            self._log('warning', "TAP mirror unavailable: %s. Snort will use physical interface only.", str(e))
            return False

        # Bring interface up
        try:
            subprocess.run(
                ['ip', 'link', 'set', self.tap_name, 'up'],
                check=True, capture_output=True, timeout=5
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self._log('warning', "Could not bring TAP up (ip link): %s", str(e))

        self._running = True
        self._writer_thread = threading.Thread(
            target=self._writer_loop,
            name='TrafficMirrorWriter',
            daemon=True
        )
        self._writer_thread.start()
        self._log('info', "Traffic mirror TAP '%s' started.", self.tap_name)
        return True

    def _writer_loop(self):
        """Background thread: drain queue and write to TAP."""
        while self._running and self._tap_fd is not None:
            try:
                packet_data = self._queue.get(timeout=0.5)
                if packet_data and self._tap_fd is not None:
                    try:
                        os.write(self._tap_fd, packet_data)
                        self._packets_injected += 1
                    except (OSError, BrokenPipeError):
                        break
            except queue.Empty:
                continue
            except Exception:
                break

    def inject(self, packet_data):
        """
        Queue a raw Ethernet frame for injection into the TAP.
        Non-blocking; drops packets if queue is full.
        """
        if not self._running or not packet_data:
            return
        try:
            self._queue.put_nowait(bytes(packet_data))
        except queue.Full:
            self._packets_dropped += 1

    def stop(self):
        """Close TAP and stop the writer thread."""
        self._running = False
        if self._writer_thread and self._writer_thread.is_alive():
            self._writer_thread.join(timeout=2)

        if self._tap_fd is not None:
            try:
                os.close(self._tap_fd)
            except OSError:
                pass
            self._tap_fd = None

        self._log('info', "Traffic mirror stopped. Injected: %d, dropped: %d",
                  self._packets_injected, self._packets_dropped)
