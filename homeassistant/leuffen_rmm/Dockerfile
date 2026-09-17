ARG BUILD_FROM
FROM ${BUILD_FROM}

# The slim agent is pure standard library: Python is all it needs.
RUN apk add --no-cache python3

# The agent code comes from the release tag this add-on version names, so a
# device only ever runs a published build. Home Assistant passes BUILD_VERSION
# (the `version` in config.yaml); AGENT_REF can be overridden to test a branch.
ARG BUILD_VERSION
ARG AGENT_REF=v${BUILD_VERSION}
ARG AGENT_SRC=https://raw.githubusercontent.com/Mischa323/leuffen-rmm-agent/${AGENT_REF}/agent
ADD ${AGENT_SRC}/haos_agent.py \
    ${AGENT_SRC}/haos_inventory.py \
    ${AGENT_SRC}/syno_agent.py \
    ${AGENT_SRC}/syno_inventory.py \
    ${AGENT_SRC}/handlers.py \
    /opt/leuffen-rmm/

WORKDIR /opt/leuffen-rmm
# with-contenv hands the process the full container environment (including
# SUPERVISOR_TOKEN) under the base image's s6 init.
CMD ["/usr/bin/with-contenv", "python3", "-u", "/opt/leuffen-rmm/haos_agent.py"]
