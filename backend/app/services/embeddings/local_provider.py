"""
Local embedding provider - runs entirely inside this container, no network
call to any third party. Document content never leaves the infrastructure
for this step, which is the actual reason this is the default provider
(see the .env.example comment and the Phase 3 architecture notes).

Runs the model through ONNX Runtime rather than sentence-transformers /
PyTorch. Same model (BAAI/bge-small-en-v1.5), same pooling the
sentence-transformers config uses for it (the [CLS] token's final hidden
state, L2-normalized), so vectors match what the PyTorch path produced to
within float rounding and existing stored embeddings stay valid. The switch
was made because PyTorch pushed the backend past Render's 512MB free-tier
memory limit during ingestion: the instance was OOM-killed mid-indexing,
leaving documents stuck in "processing".

The model and tokenizer are pre-downloaded into the Docker image at build
time (see Dockerfile) and loaded lazily, once, on first real use - not at
import time - so startup and healthchecks aren't slowed down by it.
Inference is synchronous and CPU-bound, so it runs via asyncio.to_thread.
"""
import asyncio
import threading

import numpy as np

from app.core.config import get_settings
from app.services.embeddings.base import EmbeddingProvider

settings = get_settings()

_ONNX_FILE = "onnx/model.onnx"
_TOKENIZER_FILE = "tokenizer.json"
_MAX_TOKENS = 512
# Small batches keep peak memory low: activations scale with
# batch_size x sequence_length, and a large document can produce many chunks.
_BATCH_SIZE = 16


class EmbeddingError(Exception):
    pass


def _cls_pool_and_normalize(last_hidden_state: np.ndarray) -> np.ndarray:
    """[CLS] pooling + L2 normalization - bge-small-en-v1.5's sentence-transformers config."""
    cls = last_hidden_state[:, 0, :]
    norms = np.linalg.norm(cls, axis=1, keepdims=True)
    return cls / np.clip(norms, 1e-12, None)


class LocalEmbeddingProvider(EmbeddingProvider):
    def __init__(self):
        self._session = None
        self._tokenizer = None
        self._input_names: set[str] = set()
        self._output_index = 0
        self._lock = threading.Lock()

    def _load(self):
        with self._lock:
            if self._session is not None:
                return
            try:
                import onnxruntime as ort
                from huggingface_hub import hf_hub_download
                from tokenizers import Tokenizer
            except ImportError as exc:
                raise EmbeddingError(
                    "onnxruntime/tokenizers/huggingface_hub are not installed - required because "
                    "EMBEDDING_PROVIDER=local (they ship with chromadb). Check the image was rebuilt."
                ) from exc

            repo = settings.local_embedding_model
            try:
                model_path = hf_hub_download(repo, _ONNX_FILE)
                tokenizer_path = hf_hub_download(repo, _TOKENIZER_FILE)
            except Exception as exc:
                raise EmbeddingError(f"Couldn't load the ONNX model files for {repo}: {exc}") from exc

            tokenizer = Tokenizer.from_file(tokenizer_path)
            tokenizer.enable_truncation(max_length=_MAX_TOKENS)
            pad_id = tokenizer.token_to_id("[PAD]")
            tokenizer.enable_padding(pad_id=0 if pad_id is None else pad_id, pad_token="[PAD]")

            options = ort.SessionOptions()
            # Memory over speed: no pre-allocated arena, one thread.
            options.enable_cpu_mem_arena = False
            options.intra_op_num_threads = 1
            options.inter_op_num_threads = 1
            session = ort.InferenceSession(model_path, sess_options=options, providers=["CPUExecutionProvider"])

            outputs = [o.name for o in session.get_outputs()]
            self._output_index = outputs.index("last_hidden_state") if "last_hidden_state" in outputs else 0
            self._input_names = {i.name for i in session.get_inputs()}
            self._tokenizer = tokenizer
            self._session = session

    def _encode_batch(self, texts: list[str]) -> np.ndarray:
        encodings = self._tokenizer.encode_batch(texts)
        feeds = {
            "input_ids": np.array([e.ids for e in encodings], dtype=np.int64),
            "attention_mask": np.array([e.attention_mask for e in encodings], dtype=np.int64),
        }
        if "token_type_ids" in self._input_names:
            feeds["token_type_ids"] = np.array([e.type_ids for e in encodings], dtype=np.int64)
        hidden = self._session.run(None, feeds)[self._output_index]
        return _cls_pool_and_normalize(hidden)

    async def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []

        self._load()

        def _encode_all():
            vectors = [self._encode_batch(texts[i : i + _BATCH_SIZE]) for i in range(0, len(texts), _BATCH_SIZE)]
            return np.concatenate(vectors, axis=0)

        try:
            vectors = await asyncio.to_thread(_encode_all)
        except Exception as exc:
            raise EmbeddingError(f"Local embedding inference failed: {exc}") from exc

        return vectors.tolist()
