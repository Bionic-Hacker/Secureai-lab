"""
Local (ONNX) embedding provider tests. No model download: pooling and batch
planning are tested directly, and the provider is run against a fake session
and tokenizer.
"""

import asyncio

import numpy as np

from app.services.embeddings import local_provider
from app.services.embeddings.local_provider import (
    LocalEmbeddingProvider,
    _cls_pool_and_normalize,
    _plan_batches,
)


def test_pooling_takes_the_cls_token_and_normalizes():
    hidden = np.array([[[3.0, 4.0], [100.0, 100.0]]])
    np.testing.assert_allclose(_cls_pool_and_normalize(hidden), [[0.6, 0.8]])


def test_pooling_survives_an_all_zero_vector():
    assert np.all(np.isfinite(_cls_pool_and_normalize(np.zeros((1, 3, 4)))))


def test_long_texts_are_batched_by_token_budget():
    lengths = [512] * 5 + [20] * 40
    batches = _plan_batches(lengths, budget=1024, max_batch=16)
    for batch in batches:
        assert len(batch) <= 16
        assert len(batch) * max(lengths[i] for i in batch) <= 1024 or len(batch) == 1
    assert sorted(i for b in batches for i in b) == list(range(len(lengths)))
    assert all(len(b) <= 2 for b in batches if max(lengths[i] for i in b) == 512)


def test_a_text_longer_than_the_budget_still_gets_a_batch():
    assert _plan_batches([4000], budget=1024) == [[0]]


class _Enc:
    def __init__(self, text):
        n = len(text.split())
        self.ids = [101] + [7] * n
        self.attention_mask = [1] * (n + 1)
        self.type_ids = [0] * (n + 1)
        self.n = n


class _FakeTokenizer:
    def encode_batch(self, texts):
        return [_Enc(t) for t in texts]


class _FakeSession:
    """Returns a [CLS] vector that encodes each row's real (unpadded) length."""

    def __init__(self):
        self.shapes = []
        self.feed_names = None

    def run(self, _, feeds):
        self.feed_names = sorted(feeds)
        batch, seq = feeds["input_ids"].shape
        self.shapes.append((batch, seq))
        real = feeds["attention_mask"].sum(axis=1).astype(np.float32)
        hidden = np.zeros((batch, seq, 2), dtype=np.float32)
        hidden[:, 0, 0] = real
        hidden[:, 0, 1] = 1.0
        return [hidden]


def _provider(monkeypatch, input_names):
    provider = LocalEmbeddingProvider()
    session = _FakeSession()
    provider._session = session
    provider._tokenizer = _FakeTokenizer()
    provider._input_names = set(input_names)
    monkeypatch.setattr(provider, "_load", lambda: None)
    return provider, session


def test_results_come_back_in_the_original_order(monkeypatch):
    provider, session = _provider(monkeypatch, {"input_ids", "attention_mask", "token_type_ids"})
    texts = ["a " * 3, "a " * 600, "a", "a " * 40, "a " * 600]
    vectors = np.array(asyncio.run(provider.embed_texts(texts)))
    expected_len = [len(t.split()) + 1 for t in texts]
    # each vector is normalize([len, 1]), so its direction identifies the input
    ratios = vectors[:, 0] / vectors[:, 1]
    np.testing.assert_allclose(ratios, expected_len)
    np.testing.assert_allclose(np.linalg.norm(vectors, axis=1), 1.0, rtol=1e-6)


def test_no_batch_exceeds_the_token_budget(monkeypatch):
    provider, session = _provider(monkeypatch, {"input_ids", "attention_mask"})
    asyncio.run(provider.embed_texts(["a " * 510] * 6 + ["a b c"] * 30))
    assert all(b * s <= local_provider._TOKEN_BUDGET or b == 1 for b, s in session.shapes)
    assert session.feed_names == ["attention_mask", "input_ids"]


def test_empty_input_needs_no_model(monkeypatch):
    provider = LocalEmbeddingProvider()
    monkeypatch.setattr(provider, "_load", lambda: (_ for _ in ()).throw(AssertionError("loaded")))
    assert asyncio.run(provider.embed_texts([])) == []
