"""Tests for disk and free-space wiping detector."""
import os
import numpy as np
import pytest

from afd.core.finding import Confidence
from afd.detectors import freespace


def test_entropy_and_uniformity_zeroes():
    zeros = b"\x00" * 4096
    entropy, uniformity, dom = freespace.calculate_entropy_and_uniformity(zeros)
    assert entropy == 0.0
    assert uniformity == 100.0
    assert dom == 0


def test_entropy_and_uniformity_ff():
    ff = b"\xFF" * 4096
    entropy, uniformity, dom = freespace.calculate_entropy_and_uniformity(ff)
    assert entropy == 0.0
    assert uniformity == 100.0
    assert dom == 255


def test_entropy_random_data():
    rand = os.urandom(65536)
    entropy, uniformity, _ = freespace.calculate_entropy_and_uniformity(rand)
    assert entropy > 7.9
    assert uniformity < 2.0


def test_normal_unallocated_buffer_not_flagged():
    # Simulated normal unallocated space with mixed text and fragments
    normal_data = (b"Normal fragmented file text contents here. " * 50000)
    findings = freespace.detect_from_buffer(normal_data, cfg={"chunk_size_bytes": 65536})
    assert len(findings) == 0


def test_zero_wiped_space_detected():
    # 4 chunks of 64KB zeros
    zero_data = b"\x00" * (65536 * 4)
    findings = freespace.detect_from_buffer(
        zero_data,
        cfg={"chunk_size_bytes": 65536, "min_consecutive_chunks": 3}
    )
    assert len(findings) >= 1
    assert any("Zero-fill" in f.title for f in findings)


def test_ff_pattern_wiped_space_detected():
    # 4 chunks of 64KB 0xFF
    ff_data = b"\xFF" * (65536 * 4)
    findings = freespace.detect_from_buffer(
        ff_data,
        cfg={"chunk_size_bytes": 65536, "min_consecutive_chunks": 3}
    )
    assert len(findings) >= 1
    assert any("0xFF overwrite" in f.title for f in findings)


def test_pseudorandom_wiped_space_detected():
    # 4 chunks of 64KB random data
    rand_data = os.urandom(65536 * 4)
    findings = freespace.detect_from_buffer(
        rand_data,
        cfg={"chunk_size_bytes": 65536, "min_consecutive_chunks": 3, "high_entropy_threshold": 7.9}
    )
    assert len(findings) >= 1
    assert any("Pseudorandom" in f.title for f in findings)


def test_only_fully_free_chunks_are_sampled():
    # 4 KB clusters, 16 KB chunks (4 clusters each); 4 chunks in total.
    # chunk 0: all used, chunk 1: free, chunk 2: one cluster used, chunk 3: free
    bits = [1, 1, 1, 1,  0, 0, 0, 0,  0, 1, 0, 0,  0, 0, 0, 0]
    bitmap = np.packbits(np.array(bits, dtype=np.uint8), bitorder="little").tobytes()
    offsets, total = freespace.free_chunk_offsets(bitmap, 4096, 16384, max_chunks=10)
    assert offsets == [16384, 49152] and total == 2


def test_sampling_is_capped_and_spread():
    bitmap = bytes(1000)                      # 8000 free clusters
    offsets, total = freespace.free_chunk_offsets(bitmap, 4096, 4096, max_chunks=5)
    assert total == 8000 and len(offsets) == 5
    assert offsets[0] == 0 and offsets[-1] == 7999 * 4096


def test_zero_fill_alone_is_low():
    """Never-written space on a new VM disk is zeros too, so zeros alone stay LOW."""
    findings = freespace.detect_from_buffer(b"\x00" * (65536 * 4), cfg={"chunk_size_bytes": 65536})
    assert [f.confidence for f in findings] == [Confidence.LOW]


def test_some_random_remnants_are_not_a_wipe():
    """Deleted ZIP/CAB files leave random-looking chunks; a minority of them is normal."""
    data = os.urandom(65536 * 3) + b"Normal fragmented file text contents here. " * 15000
    findings = freespace.detect_from_buffer(data, cfg={"chunk_size_bytes": 65536})
    assert not any("Pseudorandom" in f.title for f in findings)


def test_whole_volume_sample_is_capped_low():
    samples = [{"offset": i, "size": 1, "entropy": 0.0, "uniformity_pct": 100.0, "dominant_byte": 0xFF}
               for i in range(5)]
    [f] = freespace._evaluate_samples(samples, "img", freespace.merge_config(freespace.DEFAULT_CONFIG),
                                      scope="whole volume")
    assert f.confidence == Confidence.LOW and f.evidence["scope"] == "whole volume"
