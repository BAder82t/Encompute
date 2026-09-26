"""Hugging Face Transformers and PEFT for confidential fine-tuning.

Transformers supplies the architecture, PEFT supplies the LoRA adapters,
PyTorch trains. Encompute supplies ownership, policy, attestation, key
release, secure aggregation, differential privacy, lineage and
verification. Hugging Face itself provides no confidentiality.

    base = encompute.torch.huggingface("path/or/repo", revision="<commit>")
    tok = base.encompute_tokenizer
    data = encompute.torch.private_text_dataset(texts, labels, tokenizer=tok,
                                                unit_ids=patient_ids)

The supply-chain boundary is the **model package**:

1. The model owner imports a repository once, outside any confidential
   workload. The revision is resolved to an immutable commit (a local model
   gets its content digest). Credentials are used only here and are never
   stored.
2. Every file is checked: configuration, tokenizer and safetensors files
   only. Remote code (``*.py``, ``auto_map``, ``trust_remote_code``) and
   pickled weights are refused.
3. Every file is hashed, and the package's ID (``enchf1:``) commits to the
   revision, the files, the tokenizer and the library versions. The
   training spec binds the whole package.
4. Workers never download: they rebuild the architecture from its
   configuration (Transformers-native classes only) and load the sealed
   weights.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import torch

from .. import _native
from .._frontend import EncomputeError

# Workers are forked after tokenizing; keep the tokenizers library quiet
# and single-threaded there.
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

TASK = "sequence-classification"
CLASSES = {"bert": "BertForSequenceClassification",
           "distilbert": "DistilBertForSequenceClassification",
           "roberta": "RobertaForSequenceClassification"}
# The attention projections LoRA adapts by default, and the classification
# head PEFT trains in full (it is new for a pretrained encoder).
TARGETS = {"bert": ("query", "value"), "roberta": ("query", "value"),
           "distilbert": ("q_lin", "v_lin")}
HEADS = {"bert": ("classifier",), "roberta": ("classifier",),
         "distilbert": ("classifier", "pre_classifier")}
TOKENIZER_FILES = ("tokenizer.json", "tokenizer_config.json", "special_tokens_map.json",
                   "added_tokens.json", "vocab.txt", "vocab.json", "merges.txt")
# Repository files that are metadata only: never copied into a package.
METADATA = ("README.md", ".gitattributes", "LICENSE", "LICENSE.txt", "LICENSE.md")


def _refuse(message: str) -> EncomputeError:
    return EncomputeError("ENC2504", message)


def _native_call(f, *args):
    try:
        return f(*args)
    except _native.NativeError as e:
        raise EncomputeError(e.args[0], e.args[1]) from None


def _major_minor(v: str) -> str:
    return ".".join(v.split("+")[0].split(".")[:2])


def library_versions() -> Dict[str, str]:
    """The installed Transformers, PEFT and PyTorch (major.minor)."""
    import peft
    import transformers
    return {"transformers": _major_minor(transformers.__version__),
            "peft": _major_minor(peft.__version__), "torch": _major_minor(torch.__version__)}


def exact_versions() -> Dict[str, str]:
    """What actually runs (recorded in the run's provenance)."""
    import peft
    import safetensors
    import tokenizers
    import transformers
    return {"transformers": transformers.__version__, "peft": peft.__version__,
            "torch": torch.__version__, "safetensors": safetensors.__version__,
            "tokenizers": tokenizers.__version__}


def check_versions(package: dict, installed: Optional[Dict[str, str]] = None) -> None:
    """Refuses to run a package with other library versions (major.minor)
    than it was imported and approved with."""
    installed = installed or library_versions()
    for lib, want in package["libraries"].items():
        if installed.get(lib) != want:
            raise _refuse(f"installed {lib} {installed.get(lib)} is not the approved {want} "
                          "(the package binds its library versions)")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Tokenizer:
    """A package's tokenizer and its digest (bound into each dataset's
    preprocessing)."""

    hf: object
    digest: str

    def __call__(self, *args, **kwargs):
        return self.hf(*args, **kwargs)


@dataclass
class ModelPackage:
    """An imported, content-addressed model: its files and manifest."""

    path: Path
    manifest: dict
    id: str

    @property
    def model_type(self) -> str:
        return self.manifest["model_type"]

    def tokenizer(self) -> Tokenizer:
        from transformers import AutoTokenizer
        tok = AutoTokenizer.from_pretrained(str(self.path), local_files_only=True,
                                            trust_remote_code=False)
        return Tokenizer(tok, self.manifest["tokenizer_digest"])


def _check_files(files: Sequence[str]) -> List[str]:
    kept = []
    for f in sorted(files):
        if f in METADATA:
            continue
        _native_call(_native.hf_check_file, f)
        kept.append(f)
    return kept


def import_model(source: str, *, revision: Optional[str] = None, task: str = TASK,
                 num_labels: int = 2, token: Optional[str] = None,
                 trust_remote_code: bool = False, license: Optional[str] = None,
                 cache_dir: Optional[str] = None) -> ModelPackage:
    """Imports a Hugging Face model into a content-addressed package.

    ``source`` is a local directory or a Hub repository. A Hub revision is
    resolved to its immutable commit first (a branch or tag is only a way
    to find it); ``token`` authenticates only this download and is never
    stored. A local directory's revision is its content digest.
    """
    if trust_remote_code:
        raise _refuse("trust_remote_code is never allowed: a repository must not run code "
                      "inside a confidential workload. Package reviewed code into the worker "
                      "image instead")
    if task != TASK:
        raise _refuse(f"task {task!r} is not supported yet ({TASK})")
    src = Path(source)
    if src.is_dir():
        files = _check_files([p.name for p in src.iterdir() if p.is_file()])
        if any(p.is_dir() for p in src.iterdir()):
            raise _refuse(f"{source}: packages are flat directories")
        repo_id = src.name
        work = src
    else:
        from huggingface_hub import HfApi, snapshot_download
        info = HfApi().model_info(source, revision=revision or "main", token=token)
        commit = info.sha
        if revision and len(revision) == 40 and revision != commit:
            raise _refuse(f"{source}: revision {revision} resolved to {commit}")
        files = _check_files([s.rfilename for s in info.siblings if "/" not in s.rfilename])
        if not license and info.card_data:
            license = info.card_data.get("license")
        work = Path(snapshot_download(source, revision=commit, allow_patterns=files, token=token,
                                      cache_dir=cache_dir))
        repo_id = source
        revision = commit
    config = json.loads((work / "config.json").read_text())
    model_type = _native_call(_native.hf_check_config, json.dumps(config))
    if "model.safetensors.index.json" in files:
        # An index lists shard files by name; a loader opens whatever it
        # names, so it may name only this package's safetensors files.
        _native_call(_native.hf_check_index,
                     (work / "model.safetensors.index.json").read_text(), json.dumps(files))
    entries = [{"path": f, "sha256": _sha256(work / f), "size": (work / f).stat().st_size}
               for f in files]
    if src.is_dir():
        content = hashlib.sha256("".join(f"{e['path']}\0{e['sha256']}\n" for e in entries)
                                 .encode()).hexdigest()
        if revision and revision != f"sha256:{content}":
            raise _refuse(f"{source}: its content is not revision {revision}")
        revision = f"sha256:{content}"
    by = {e["path"]: e["sha256"] for e in entries}
    manifest = {
        "version": 1, "repo_id": repo_id, "revision": revision, "model_type": model_type,
        "model_class": CLASSES[model_type], "task": task, "num_labels": int(num_labels),
        "config_digest": by["config.json"], "tokenizer_digest": "0" * 64,
        "files": entries, "libraries": library_versions(), "license": license,
    }
    # The tokenizer digest over the tokenizer files, as Rust defines it.
    manifest["tokenizer_digest"] = _native_call(_native.hf_tokenizer_digest, json.dumps(manifest))
    pid = _native_call(_native.hf_package_id, json.dumps(manifest))
    # The package: a private copy of exactly the checked files.
    dest = Path(tempfile.mkdtemp(prefix=f"enchf1-{pid[:12]}-"))
    for f in files:
        shutil.copyfile(work / f, dest / f)
        if _sha256(dest / f) != by[f]:
            raise _refuse(f"{f} changed while it was being imported")
    return ModelPackage(dest, manifest, pid)


def from_config(config: dict, task: str = TASK) -> torch.nn.Module:
    """Builds a Transformers-native model from its configuration, with no
    weights and no remote code: the factory workers rebuild the base model
    with. Eager attention, so per-example gradients can vectorize."""
    from transformers import AutoConfig, AutoModelForSequenceClassification
    if task != TASK:
        raise _refuse(f"task {task!r} is not supported yet")
    _native_call(_native.hf_check_config, json.dumps(config))
    c = dict(config)
    model_type = c.pop("model_type")
    conf = AutoConfig.for_model(model_type, **c)
    return AutoModelForSequenceClassification.from_config(conf, attn_implementation="eager")


def build_config(model: torch.nn.Module) -> dict:
    """A loaded model's configuration, without machine-specific fields."""
    c = model.config.to_dict()
    for k in ("_name_or_path", "transformers_version", "_attn_implementation_autoset",
              "torch_dtype", "attn_implementation"):
        c.pop(k, None)
    return c


def huggingface(source: str, *, revision: Optional[str] = None, task: str = TASK,
                num_labels: int = 2, token: Optional[str] = None,
                trust_remote_code: bool = False, seed: int = 0) -> torch.nn.Module:
    """Imports a Hugging Face model (see :func:`import_model`) and loads it
    for ``project.model(..., module=...)``. The classification head, new
    for a pretrained encoder, is initialized from ``seed``."""
    from transformers import AutoModelForSequenceClassification
    pkg = import_model(source, revision=revision, task=task, num_labels=num_labels, token=token,
                       trust_remote_code=trust_remote_code)
    torch.manual_seed(seed)
    model = AutoModelForSequenceClassification.from_pretrained(
        str(pkg.path), local_files_only=True, use_safetensors=True, trust_remote_code=False,
        num_labels=num_labels, attn_implementation="eager")
    model.encompute_factory = "encompute.torch.hf:from_config"
    model.encompute_kwargs = {"config": build_config(model), "task": task}
    model.encompute_hf = pkg
    model.encompute_tokenizer = pkg.tokenizer()
    return model


# --- PEFT ----------------------------------------------------------------------


def peft_config(model_type: str, rank: int, alpha: int, target_modules: Sequence[str],
                dropout: float = 0.0, bias: str = "none",
                modules_to_save: Optional[Sequence[str]] = None,
                init_lora_weights: str = "true", adapter_name: str = "default") -> dict:
    """The PEFT LoRA configuration the training spec binds."""
    from .finetune import _exact
    return {"peft_type": "LORA", "r": int(rank), "lora_alpha": int(alpha),
            "lora_dropout": _exact(dropout), "target_modules": sorted(target_modules),
            "bias": bias, "modules_to_save": sorted(modules_to_save or HEADS[model_type]),
            "task_type": "SEQ_CLS", "init_lora_weights": init_lora_weights,
            "adapter_name": adapter_name, "library": library_versions()["peft"]}


def apply_peft(model: torch.nn.Module, pc: dict, seed: int = 0) -> torch.nn.Module:
    """Adds PEFT LoRA adapters (deterministically, from ``seed``)."""
    from peft import LoraConfig, get_peft_model
    torch.manual_seed(seed)
    cfg = LoraConfig(r=pc["r"], lora_alpha=pc["lora_alpha"],
                     lora_dropout=float(pc["lora_dropout"]),
                     target_modules=list(pc["target_modules"]), bias=pc["bias"],
                     modules_to_save=list(pc["modules_to_save"]), task_type="SEQ_CLS",
                     init_lora_weights=True if pc["init_lora_weights"] == "true" else "gaussian")
    return get_peft_model(model, cfg, adapter_name=pc["adapter_name"])


# --- tests and examples: a tiny model, built offline ---------------------------

WORDS = ("fever cough stable normal rash pain tired dizzy calm clear healthy fine well "
         "bleeding chest breath swelling nausea sepsis alert resting eating walking").split()


def synthetic_notes(seed: int, n: int, risk: Sequence[str], purity: float = 0.8):
    """Synthetic clinical notes: six words, most drawn from ``risk`` words
    when the label is 1 and from the other words when it is 0."""
    import random
    r = random.Random(seed)
    other = [w for w in WORDS if w not in risk]
    texts, labels = [], []
    for _ in range(n):
        sick = r.random() < 0.5
        pool = list(risk) if sick else other
        texts.append(" ".join(r.choice(pool) if r.random() < purity else r.choice(WORDS)
                              for _ in range(6)))
        labels.append(int(sick))
    return texts, labels


# The model owner's pretraining task: related to the hospitals' task, not
# the same (a shifted set of risk words).
PRETRAINING_RISK = WORDS[9:20]


def write_tiny_model(path: str, model_type: str = "bert", seed: int = 0,
                     pretrain_steps: int = 300) -> Path:
    """Writes a tiny Transformers model (2 layers, width 32) and a
    word-level tokenizer to ``path``, in safetensors, as a repository would
    hold it. It is briefly pretrained on a related synthetic task, as a
    real base model would be, so fine-tuning has useful features to adapt.
    No download: for tests and examples."""
    from transformers import (BertConfig, BertForSequenceClassification, BertTokenizerFast,
                              DistilBertConfig, DistilBertForSequenceClassification)
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    vocab = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"] + list(WORDS)
    (p / "vocab.txt").write_text("\n".join(vocab) + "\n")
    tok = BertTokenizerFast(vocab_file=str(p / "vocab.txt"), do_lower_case=True)
    (p / "vocab.txt").unlink()
    tok.save_pretrained(str(p))
    torch.manual_seed(seed)
    if model_type == "bert":
        m = BertForSequenceClassification(BertConfig(
            vocab_size=len(vocab), hidden_size=32, num_hidden_layers=2, num_attention_heads=2,
            intermediate_size=64, max_position_embeddings=64))
    elif model_type == "distilbert":
        m = DistilBertForSequenceClassification(DistilBertConfig(
            vocab_size=len(vocab), dim=32, n_layers=2, n_heads=2, hidden_dim=64,
            max_position_embeddings=64))
    else:
        raise ValueError(model_type)
    if pretrain_steps:
        from . import tasks
        texts, labels = synthetic_notes(seed + 11, 3000, PRETRAINING_RISK, purity=0.7)
        enc = tok(texts, max_length=16, padding="max_length", truncation=True,
                  return_tensors="pt")
        batch = {"input_ids": enc["input_ids"], "attention_mask": enc["attention_mask"],
                 "labels": torch.tensor(labels)}
        opt = torch.optim.Adam(m.parameters(), lr=3e-3)
        g = torch.Generator().manual_seed(seed)
        m.train()
        for _ in range(pretrain_steps):
            idx = torch.randint(0, len(texts), (64,), generator=g)
            opt.zero_grad()
            tasks.SEQUENCE_CLASSIFICATION.losses(m, tasks.select(batch, idx)).mean().backward()
            opt.step()
    m.save_pretrained(str(p), safe_serialization=True)
    return p
