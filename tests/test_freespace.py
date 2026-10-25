"""Tests for disk and free-space wiping detector."""
import os
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
