FROM python:3.12-slim
WORKDIR /worker
COPY . WazuhAnalyzer
RUN test -f WazuhAnalyzer/requirements.txt && pip install --no-cache-dir -r WazuhAnalyzer/requirements.txt
ENTRYPOINT ["python", "WazuhAnalyzer/wazuh_analyzer.py"]
