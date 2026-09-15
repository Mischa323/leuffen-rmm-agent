"""Decoding for the remote-desktop stream.

The agent negotiates one of two wire formats (see `agent/screen.py`):

  * **H.264** Annex-B access units when the viewer advertises `h264` and the
    agent has PyAV -- inter-frame deltas, so far less bandwidth for the same
    picture. The browser viewer decodes these with WebCodecs; here it is PyAV,
    which the agent build already depends on.
  * **JPEG** full frames otherwise -- the universal fallback.

Both paths hand back a PIL image; the window does the scaling and painting.
Clipboard replies arrive on the same binary channel behind an `LRMMCLIP` magic
(JPEG always starts FF D8 FF, so there is no collision).
"""
from __future__ import annotations

CLIP_MAGIC = b"LRMMCLIP"

_av_error: str | None = None


def h264_available() -> bool:
    """True if this build can decode H.264 (PyAV present and importable)."""
    global _av_error
    try:
        import av  # noqa: F401
        _av_error = None
        return True
    except Exception as exc:
        _av_error = repr(exc)
        return False


def h264_error() -> str | None:
    return _av_error


def is_clipboard(data: bytes) -> bool:
    return data[:len(CLIP_MAGIC)] == CLIP_MAGIC


def clipboard_text(data: bytes) -> str:
    return data[len(CLIP_MAGIC):].decode("utf-8", "replace")


def decode_jpeg(data: bytes):
    """JPEG bytes -> PIL image (None if the frame is corrupt)."""
    import io

    from PIL import Image
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
        return img.convert("RGB") if img.mode != "RGB" else img
    except Exception:
        return None


class H264Decoder:
    """Stateful Annex-B decoder. Feed access units, get zero or more images.

    Like the browser viewer, delta frames before the first keyframe are dropped:
    a session joined mid-stream would otherwise paint garbage until the next IDR.
    """

    def __init__(self) -> None:
        import av
        self._ctx = av.CodecContext.create("h264", "r")
        self._saw_key = False
        self.frames_out = 0

    @staticmethod
    def is_keyframe(data: bytes) -> bool:
        """True if the access unit carries an IDR/SPS/PPS NAL (types 5/7/8)."""
        n = len(data)
        for i in range(n - 4):
            if data[i] == 0 and data[i + 1] == 0 and \
                    (data[i + 2] == 1 or (data[i + 2] == 0 and data[i + 3] == 1)):
                nal = data[i + 3] if data[i + 2] == 1 else data[i + 4]
                if (nal & 0x1F) in (5, 7, 8):
                    return True
        return False

    def decode(self, data: bytes) -> list:
        if not self._saw_key:
            if not self.is_keyframe(data):
                return []
            self._saw_key = True
        out = []
        try:
            for packet in self._ctx.parse(data):
                for frame in self._ctx.decode(packet):
                    image = _frame_to_image(frame)
                    if image is not None:
                        out.append(image)
        except Exception:
            # A damaged unit must not kill the session -- wait for the next
            # keyframe and carry on.
            self._saw_key = False
            return out
        self.frames_out += len(out)
        return out

    def close(self) -> None:
        self._ctx = None


def _frame_to_image(frame):
    """PyAV frame -> PIL image, honouring the plane's stride.

    `VideoFrame.to_image()` would do this, but it routes through numpy in current
    PyAV versions; doing it directly keeps numpy out of the MSI.
    """
    from PIL import Image
    try:
        rgb = frame.reformat(format="rgb24")
        plane = rgb.planes[0]
        width, height = rgb.width, rgb.height
        buf = bytes(plane)
        stride = plane.line_size
        if stride == width * 3:
            return Image.frombytes("RGB", (width, height), buf)
        rows = [buf[y * stride:y * stride + width * 3] for y in range(height)]
        return Image.frombytes("RGB", (width, height), b"".join(rows))
    except Exception:
        return None
