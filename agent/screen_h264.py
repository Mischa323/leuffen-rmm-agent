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


def available() -> bool:
    """True if H.264 encoding is possible in this build (PyAV present)."""
    try:
        import av  # noqa: F401
        return True
    except Exception:
        return False


# WebCodecs codec string the browser configures its decoder with. We pin the
# encoder to Constrained Baseline 3.1 (avc1.42E01F) for the widest hardware
# decode support in browsers; the number is profile(42)/constraints(E0)/level(1F).
CODEC_STRING = "avc1.42E01F"


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
        # better). zerolatency = no B-frames / lookahead; keyint gives ~2s GOP so
        # a joining/recovering viewer gets a keyframe quickly. repeat-headers puts
        # SPS/PPS in front of every IDR (needed for Annex-B decoder recovery).
        crf = int(round(30 - (max(10, min(quality, 90)) - 10) / 80 * 12))
        gop = max(self.fps * 2, 30)
        cc.options = {
            "preset": "ultrafast",
            "tune": "zerolatency",
            "crf": str(crf),
            "x264-params": f"keyint={gop}:min-keyint={self.fps}:scenecut=0:repeat-headers=1",
        }
        self._cc = cc
        self._av = av

    def encode(self, pil_rgb_image) -> list[bytes]:
        """Encode one frame (a PIL RGB Image). Returns Annex-B NAL byte strings."""
        frame = self._av.VideoFrame.from_image(pil_rgb_image)
        frame = frame.reformat(width=self.width, height=self.height, format="yuv420p")
        frame.pts = self._pts
        frame.time_base = Fraction(1, self.fps)
        self._pts += 1
        out = []
        for pkt in self._cc.encode(frame):
            b = bytes(pkt)
            if b:
                out.append(b)
        return out

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
