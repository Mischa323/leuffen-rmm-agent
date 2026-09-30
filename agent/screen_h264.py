"""Optional H.264 encoder for the remote-desktop stream (Phase 1).

Wraps PyAV / libx264 so the screen streamer can send **H.264 Annex-B** frames
instead of full JPEGs — inter-frame deltas cut bandwidth enormously, so the same
link carries much higher quality/resolution. The browser decodes with the
WebCodecs ``VideoDecoder`` API.

Everything here is **optional and lazy**: if PyAV (``av``) isn't available the
streamer simply falls back to JPEG, so the agent keeps working unchanged. Nothing
in this module is imported at agent start-up.

Output is Annex-B (start-code delimited NALs) with SPS/PPS repeated on every
keyframe, so a viewer can (re)configure its decoder from any keyframe and never
needs an out-of-band ``avcC`` description.
"""
from __future__ import annotations

from fractions import Fraction


_import_error: str | None = None


def available() -> bool:
    """True if H.264 encoding is possible in this build (PyAV present). Records
    the import failure (see :func:`import_error`) so the streamer can log *why* it
    fell back to JPEG — PyInstaller can bundle ``av`` but miss a transitive DLL."""
    global _import_error
    try:
        import av  # noqa: F401
        _import_error = None
        return True
    except Exception as e:  # pragma: no cover
        _import_error = repr(e)
        return False


def import_error() -> str | None:
    """The last PyAV import error string (None if it imported fine)."""
    return _import_error


# WebCodecs codec string the browser configures its decoder with. We pin the
# encoder to Constrained Baseline 3.1 (avc1.42E01F) for the widest hardware
# decode support in browsers; the number is profile(42)/constraints(E0)/level(1F).
CODEC_STRING = "avc1.42E01F"

# A keyframe is a whole screen -- a few hundred kB -- and on a device with a
# modest upload it takes more than half a second to get out, with every frame
# after it waiting behind it. Sent every two seconds, that was a stutter every
# two seconds, and on a still screen four fifths of the traffic. The stream is
# TCP, so nothing is ever lost and a keyframe is only needed to start or to
# recover: the viewer or the server asks for one then (see request_keyframe),
# and this is merely the safety net for a viewer too old to ask.
KEYFRAME_EVERY_S = 30


class H264Encoder:
    """One libx264 encoder for a fixed frame size. Feed PIL RGB frames, get a
    list of Annex-B byte strings (usually one per frame; empty while the encoder
    buffers). Recreate it if the capture size changes."""

    def __init__(self, width: int, height: int, fps: int, quality: int = 78):
        import av
        # Even dimensions are required by yuv420p.
        self.width = width - (width % 2)
        self.height = height - (height % 2)
        self.fps = max(1, int(fps))
        self._pts = 0
        cc = av.CodecContext.create("libx264", "w")
        cc.width = self.width
        cc.height = self.height
        cc.pix_fmt = "yuv420p"
        cc.framerate = Fraction(self.fps, 1)
        cc.time_base = Fraction(1, self.fps)
        # A CRF maps the 10..90 JPEG-style quality onto x264's 18..30 (lower is
        # better). zerolatency = no B-frames / lookahead. Keyframes come when
        # asked for (see KEYFRAME_EVERY_S); forced-idr makes an asked-for one a
        # real IDR, and repeat-headers puts SPS/PPS in front of every IDR, so a
        # decoder can start from any of them.
        crf = int(round(30 - (max(10, min(quality, 90)) - 10) / 80 * 12))
        gop = max(self.fps * KEYFRAME_EVERY_S, 30)
        cc.options = {
            "preset": "ultrafast",
            "tune": "zerolatency",
            "crf": str(crf),
            "forced-idr": "1",
            "x264-params": f"keyint={gop}:min-keyint={self.fps}:scenecut=0:repeat-headers=1",
        }
        self._cc = cc
        self._av = av
        self._want_key = False

    def request_keyframe(self) -> None:
        """Make the next frame a keyframe (for a viewer that starts or recovers)."""
        self._want_key = True

    def _mark(self, frame) -> None:
        if not self._want_key:
            return
        self._want_key = False
        try:
            frame.pict_type = self._av.video.frame.PictureType.I
        except Exception:
            frame.pict_type = "I"            # older PyAV

    def encode(self, pil_rgb_image) -> list[bytes]:
        """Encode one frame (a PIL RGB Image). Returns Annex-B NAL byte strings."""
        frame = self._av.VideoFrame.from_image(pil_rgb_image)
        frame = frame.reformat(width=self.width, height=self.height, format="yuv420p")
        frame.pts = self._pts
        frame.time_base = Fraction(1, self.fps)
        self._pts += 1
        self._mark(frame)
        out = []
        for pkt in self._cc.encode(frame):
            b = bytes(pkt)
            if b:
                out.append(b)
        return out

    def encode_bgra(self, bgra: bytes, src_width: int, src_height: int) -> list[bytes]:
        """Encode one frame straight from a screen grab's BGRA buffer.

        The PIL route costs two full-frame copies and a separate resample before
        colour conversion even starts. Handing the raw pixels to swscale does the
        conversion *and* the downscale in a single SIMD pass. Measured on a
        2560x1440 desktop streaming at 2400 wide: 65.6 -> 43.2 ms per frame,
        which lifts the ceiling from 15 fps to 23 -- past the 20 fps the
        'balanced' preset asks for.
        """
        av = self._av
        frame = av.VideoFrame(src_width, src_height, "bgra")
        plane = frame.planes[0]
        if plane.line_size == src_width * 4:
            plane.update(bgra)
        else:
            # The frame's rows carry alignment padding: copy row by row.
            view = memoryview(plane)
            row = src_width * 4
            for y in range(src_height):
                start = y * plane.line_size
                view[start:start + row] = bgra[y * row:(y + 1) * row]
        frame = frame.reformat(width=self.width, height=self.height,
                               format="yuv420p", interpolation="BILINEAR")
        frame.pts = self._pts
        frame.time_base = Fraction(1, self.fps)
        self._pts += 1
        self._mark(frame)
        return [b for b in (bytes(p) for p in self._cc.encode(frame)) if b]

    def flush(self) -> list[bytes]:
        out = []
        try:
            for pkt in self._cc.encode(None):
                b = bytes(pkt)
                if b:
                    out.append(b)
        except Exception:
            pass
        return out


# H.264 NAL unit types that mark a keyframe / parameter sets (for the viewer to
# tag EncodedVideoChunk as 'key' vs 'delta'). 5 = IDR slice, 7 = SPS, 8 = PPS.
KEYFRAME_NAL_TYPES = (5, 7, 8)
