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

FROM rust:1.98-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv \
 && rm -rf /var/lib/apt/lists/* && python3 -m venv /venv \
 && /venv/bin/pip install --no-cache-dir maturin==1.7.4
COPY . .
RUN cargo build --release --locked -p encompute-cli \
 && /venv/bin/maturin build --release --locked -m crates/encompute-py/Cargo.toml -o /wheels

FROM python:3.11-slim-bookworm AS runtime
COPY deploy/confidential-space-training/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu \
      -r /app/requirements.txt
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
