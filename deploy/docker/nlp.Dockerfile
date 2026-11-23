# The language-model service (Onshore Commercial Licence, see ee/LICENSE).
# One engine per image, chosen at build time, with its model built in, because the
# running container has no outbound network:
#
#   ENGINE=spacy         MODEL=en_core_web_lg   (default; any spaCy pipeline package)
#   ENGINE=transformers  MODEL=dslim/bert-base-NER  (any Hugging Face token-classification model)
#   ENGINE=stanza        MODEL=en           (a Stanza language code)
FROM python:3.12-slim-bookworm
ARG ENGINE=spacy
ARG MODEL=
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 \
    HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 STANZA_RESOURCES_DIR=/models/stanza
RUN set -eu; \
    case "$ENGINE" in \
      spacy) \
        pip install -q "spacy==3.8.2" "click>=8.1"; \
        m="${MODEL:-en_core_web_lg}"; python -m spacy download "$m" >/dev/null; \
        echo "$m" > /model ;; \
      transformers) \
        pip install -q --index-url https://download.pytorch.org/whl/cpu "torch==2.5.1"; \
        pip install -q "transformers==4.46.3" "huggingface_hub==0.26.2"; \
        m="${MODEL:-dslim/bert-base-NER}"; \
        HF_HUB_OFFLINE=0 python -c "import sys; from huggingface_hub import snapshot_download; snapshot_download(sys.argv[1], local_dir='/models/hf', allow_patterns=['*.json','*.txt','*.safetensors','*.model'])" "$m"; \
        echo /models/hf > /model ;; \
      stanza) \
        pip install -q --index-url https://download.pytorch.org/whl/cpu "torch==2.5.1"; \
        pip install -q "stanza==1.9.2"; \
        m="${MODEL:-en}"; python -c "import sys, stanza; stanza.download(sys.argv[1], processors='tokenize,ner', model_dir='/models/stanza')" "$m"; \
        echo "$m" > /model ;; \
      *) echo "ENGINE must be spacy, transformers or stanza" >&2; exit 1 ;; \
    esac; \
    echo "$ENGINE" > /engine; chmod -R a+rX /models 2>/dev/null || true
COPY ee/nlp/server.py /app/server.py
USER 65532:65532
ENTRYPOINT ["sh", "-c", "RV_NLP_ENGINE=\"${RV_NLP_ENGINE:-$(cat /engine)}\" RV_NLP_MODEL=\"${RV_NLP_MODEL:-$(cat /model)}\" exec python /app/server.py"]
