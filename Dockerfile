FROM scratch
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/github-app-sts-server /github-app-sts-server
ENTRYPOINT ["/github-app-sts-server"]
