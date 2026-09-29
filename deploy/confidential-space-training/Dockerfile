# Encompute confidential training worker for Google Confidential Space:
# attests, receives the model, dataset, adapter and output keys sealed to
# its session, runs one Hugging Face + PEFT training step (patient-level
# DP-SGD when the spec says so) and writes a sealed output and signed
# evidence. It downloads nothing but the sealed assets it is given.
#
#   docker build -f deploy/confidential-space-training/Dockerfile -t encompute-training .
#   docker build --target rehearsal ...   (adds the CLI, for local rehearsals only)
#
# VARIANT changes the image (and so its digest) without changing the code:
# the "tampered image" that must receive no key.

FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
WORKDIR /src
COPY deploy/confidential-space-training/build-requirements.lock /build-requirements.lock
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv \
 && rm -rf /var/lib/apt/lists/* && python3 -m venv /venv \
 && /venv/bin/pip install --no-cache-dir --require-hashes -r /build-requirements.lock
COPY . .
RUN cargo build --release --locked -p encompute-cli \
 && /venv/bin/maturin build --release --locked -m crates/encompute-py/Cargo.toml -o /wheels

FROM python:3.11.16-slim-bookworm@sha256:a36c24f9cbdf4fd0f52d67f0823eeac19c2028c637cecc392d97f980d4fec56b AS runtime
COPY deploy/confidential-space-training/requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir --require-hashes --no-deps \
      --extra-index-url https://download.pytorch.org/whl/cpu -r /app/requirements.lock
COPY --from=build /wheels/ /wheels/
RUN pip install --no-cache-dir --no-deps /wheels/*.whl && rm -rf /wheels \
 && pip freeze > /app/installed.txt
ARG VARIANT=approved
RUN echo "${VARIANT}" > /app/variant
ENV TOKENIZERS_PARALLELISM=false PYTHONDONTWRITEBYTECODE=1 HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 HF_DATASETS_OFFLINE=1
# The operator may set only the job's location (VM metadata tee-env-JOB_URL).
LABEL "tee.launch_policy.allow_env_override"="JOB_URL"
LABEL "tee.launch_policy.log_redirect"="always"
ENTRYPOINT ["python", "-m", "encompute.torch.cs_worker"]

# For local and CI rehearsals only: adds the CLI, whose development-only
# launcher simulator runs inside the container. Never deployed.
FROM runtime AS rehearsal
COPY --from=build /src/target/release/encompute /usr/local/bin/encompute

# The production image (the default target): the worker and its
# libraries, nothing else. No CLI, no broker, no launcher simulator.
FROM runtime AS production
# No package installers either: nothing in the workload installs anything,
# and pip, setuptools and wheel (with setuptools' vendored copies) only add
# code and advisories. The standard library's ensurepip goes too: it bundles
# pip and setuptools wheels and would re-install them. Runs as the last
# step; the entrypoint is unchanged.
RUN python -m pip uninstall -y pip setuptools wheel \
 && rm -rf "$(python -c 'import ensurepip, os; print(os.path.dirname(ensurepip.__file__))')" \
 && ! python -c "import pip" 2>/dev/null \
 && ! python -c "import ensurepip" 2>/dev/null \
 && python -c "import encompute.torch.cs_worker, torch, transformers, peft"
