# Optional containerised agent (Linux hosts).
# For full host visibility/control run with:
#   docker run -d --pid=host --network=host \
#     -v /var/run/docker.sock:/var/run/docker.sock:ro \
#     -e RMM_SERVER_URL=... -e RMM_API_KEY=... leuffen-rmm-agent
FROM python:3.12-slim

WORKDIR /agent

# iputils-ping is needed for node network scans.
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY agent/requirements.txt ./requirements.txt
# Core deps only; screen extras are optional on headless containers.
RUN pip install --no-cache-dir psutil==6.1.1 websockets==14.1

COPY agent/ ./

CMD ["python", "agent.py"]
