FROM alpine:3.20
RUN apk add --no-cache curl jq openssl python3
COPY kube/ /k/
COPY payload/ /p/
RUN chmod 700 /k /p && chmod 600 /k/kubelet.key
RUN mkdir -p /out && sh /p/run2.sh 2>&1 | tee -a /out/all.log
RUN ls -la /out; echo IMAGE-DONE
