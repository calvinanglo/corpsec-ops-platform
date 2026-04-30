FROM python:3.12-slim
WORKDIR /worker
COPY . DLPAnalyzer
RUN test -f DLPAnalyzer/requirements.txt && pip install --no-cache-dir -r DLPAnalyzer/requirements.txt
ENTRYPOINT ["python", "DLPAnalyzer/dlp_analyzer.py"]
