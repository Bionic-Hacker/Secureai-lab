"""
Local embedding provider - runs entirely inside this container, no network
call to any third party. Document content never leaves the infrastructure
for this step, which is the actual reason this is the default provider
(see the .env.example comment and the Phase 3 architecture notes).

Runs BAAI/bge-small-en-v1.5 through ONNX Runtime rather than
sentence-transformers / PyTorch, with the same pooling the
sentence-transformers config uses ([CLS] token, L2-normalized): parity was
verified at cosine 1.000000 against the PyTorch path.

Memory, measured rather than assumed (Render's free tier allows 512MB and the
app itself idles around 150-185MB):
  - PyTorch pushed ingestion past 512MB -> moved to ONNX Runtime.
  - ONNX alone still peaked at ~760MB on long inputs. The cost wasn't the
    model weights but attention activations, which grow with
    batch_size x sequence_length^2: sixteen 512-token chunks at once was the
    spike. Disabling graph optimization (~870MB) and an int8-quantized model
    (~950MB, and slightly different vectors) both measured WORSE.
  - So batches are sized by a token budget instead of a fixed count: many
    short chunks can still share a batch, but long ones run one or two at a
    time. Vectors are identical either way - padding doesn't change the
    [CLS] output, and the original order is restored before returning.

The model and tokenizer are pre-downloaded into the Docker image at build
time (see Dockerfile) and loaded lazily, once, on first real use. Inference
is synchronous and CPU-bound, so it runs via asyncio.to_thread.
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
_MAX_BATCH = 16
# Upper bound on (texts in a batch) x (longest text in that batch, in tokens).
# 1024 = two full-length 512-token chunks, or sixteen 64-token ones.
_TOKEN_BUDGET = 1024


class EmbeddingError(Exception):
    pass


def _cls_pool_and_normalize(last_hidden_state: np.ndarray) -> np.ndarray:
    """[CLS] pooling + L2 normalization - bge-small-en-v1.5's sentence-transformers config."""
    cls = last_hidden_state[:, 0, :]
    norms = np.linalg.norm(cls, axis=1, keepdims=True)
    return cls / np.clip(norms, 1e-12, None)


def _plan_batches(lengths: list[int], budget: int = _TOKEN_BUDGET, max_batch: int = _MAX_BATCH) -> list[list[int]]:
    """Group text indices (longest first) so each batch's size x longest length stays within budget.
    A single text longer than the budget still gets its own batch of one."""
    order = sorted(range(len(lengths)), key=lambda i: lengths[i], reverse=True)
    batches: list[list[int]] = []
    current: list[int] = []
    longest = 0
    for i in order:
        n = lengths[i]
        widest = max(longest, n)
        if current and (len(current) >= max_batch or (len(current) + 1) * widest > budget):
            batches.append(current)
            current, widest = [], n
        current.append(i)
        longest = widest
    if current:
        batches.append(current)
    return batches


class LocalEmbeddingProvider(EmbeddingProvider):
    def __init__(self):
        self._session = None
        self._tokenizer = None
        self._pad_id = 0
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
            tokenizer.no_padding()  # padding is done per batch in _encode_all
            pad_id = tokenizer.token_to_id("[PAD]")

            options = ort.SessionOptions()
            # Memory over speed: no pre-allocated arena, one thread. Graph
            # optimization stays ON - measured lower peak memory than off.
            options.enable_cpu_mem_arena = False
            options.intra_op_num_threads = 1
            options.inter_op_num_threads = 1
            session = ort.InferenceSession(model_path, sess_options=options, providers=["CPUExecutionProvider"])

            outputs = [o.name for o in session.get_outputs()]
            self._output_index = outputs.index("last_hidden_state") if "last_hidden_state" in outputs else 0
            self._input_names = {i.name for i in session.get_inputs()}
            self._pad_id = 0 if pad_id is None else pad_id
            self._tokenizer = tokenizer
            self._session = session

    def _run(self, encodings: list) -> np.ndarray:
        width = max(len(e.ids) for e in encodings)
        ids = np.full((len(encodings), width), self._pad_id, dtype=np.int64)
        mask = np.zeros((len(encodings), width), dtype=np.int64)
        types = np.zeros((len(encodings), width), dtype=np.int64)
        for row, e in enumerate(encodings):
            n = len(e.ids)
            ids[row, :n] = e.ids
            mask[row, :n] = e.attention_mask
            types[row, :n] = e.type_ids
        feeds = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self._input_names:
            feeds["token_type_ids"] = types
        hidden = self._session.run(None, feeds)[self._output_index]
        return _cls_pool_and_normalize(hidden)

    def _encode_all(self, texts: list[str]) -> np.ndarray:
        encodings = self._tokenizer.encode_batch(texts)
        results: list = [None] * len(texts)
        for batch in _plan_batches([len(e.ids) for e in encodings]):
            vectors = self._run([encodings[i] for i in batch])
            for row, i in enumerate(batch):
                results[i] = vectors[row]
        return np.stack(results)

    async def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []

        self._load()
        try:
            vectors = await asyncio.to_thread(self._encode_all, texts)
        except Exception as exc:
            raise EmbeddingError(f"Local embedding inference failed: {exc}") from exc

        return vectors.tolist()
