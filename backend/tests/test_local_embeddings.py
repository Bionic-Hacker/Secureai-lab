"""
Local (ONNX) embedding provider tests. No model download: pooling is tested
directly, and the provider's batching/feeds are tested against a fake
session and tokenizer.
"""

import asyncio

import numpy as np

from app.services.embeddings import local_provider
from app.services.embeddings.local_provider import LocalEmbeddingProvider, _cls_pool_and_normalize


def test_pooling_takes_the_cls_token_and_normalizes():
    hidden = np.array([[[3.0, 4.0], [100.0, 100.0]]])  # batch 1, 2 tokens, dim 2
    out = _cls_pool_and_normalize(hidden)
    np.testing.assert_allclose(out, [[0.6, 0.8]])


def test_pooling_survives_an_all_zero_vector():
    out = _cls_pool_and_normalize(np.zeros((1, 3, 4)))
    assert np.all(np.isfinite(out))


class _Enc:
    def __init__(self, n):
        self.ids = [101] + [7] * n
        self.attention_mask = [1] * (n + 1)
        self.type_ids = [0] * (n + 1)


class _FakeTokenizer:
    def encode_batch(self, texts):
        width = max(len(t) for t in texts)
        encs = [_Enc(len(t)) for t in texts]
        for e in encs:  # pad like the real tokenizer does
            pad = width + 1 - len(e.ids)
            e.ids += [0] * pad
            e.attention_mask += [0] * pad
            e.type_ids += [0] * pad
        return encs


class _FakeSession:
    def __init__(self):
        self.batch_sizes = []
        self.feed_names = None

    def run(self, _, feeds):
        self.feed_names = sorted(feeds)
        batch, seq = feeds["input_ids"].shape
        self.batch_sizes.append(batch)
        hidden = np.ones((batch, seq, 4), dtype=np.float32)
        return [hidden]


def _provider(monkeypatch, input_names):
    provider = LocalEmbeddingProvider()
    session = _FakeSession()
    provider._session = session
    provider._tokenizer = _FakeTokenizer()
    provider._input_names = set(input_names)
    monkeypatch.setattr(provider, "_load", lambda: None)
    return provider, session


def test_embeds_in_small_batches_and_returns_unit_vectors(monkeypatch):
    provider, session = _provider(monkeypatch, {"input_ids", "attention_mask", "token_type_ids"})
    texts = [f"chunk {i}" for i in range(local_provider._BATCH_SIZE * 2 + 3)]
    vectors = asyncio.run(provider.embed_texts(texts))
    assert len(vectors) == len(texts)
    assert max(session.batch_sizes) <= local_provider._BATCH_SIZE
    np.testing.assert_allclose(np.linalg.norm(np.array(vectors), axis=1), 1.0, rtol=1e-6)
    assert session.feed_names == ["attention_mask", "input_ids", "token_type_ids"]


def test_token_type_ids_only_sent_when_the_model_expects_them(monkeypatch):
    provider, session = _provider(monkeypatch, {"input_ids", "attention_mask"})
    asyncio.run(provider.embed_texts(["hello"]))
    assert session.feed_names == ["attention_mask", "input_ids"]


def test_empty_input_needs_no_model(monkeypatch):
    provider = LocalEmbeddingProvider()
    monkeypatch.setattr(provider, "_load", lambda: (_ for _ in ()).throw(AssertionError("loaded")))
    assert asyncio.run(provider.embed_texts([])) == []
