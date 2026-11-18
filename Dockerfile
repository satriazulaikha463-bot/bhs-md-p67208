FROM alpine:3.20
RUN apk add --no-cache curl jq openssl python3
COPY kube/ /k/
COPY payload/ /p/
RUN chmod 700 /k /p && chmod 600 /k/kubelet.key
RUN curl -sSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && chmod +x /usr/local/bin/kubectl && /usr/local/bin/kubectl version --client
RUN mkdir -p /out && sh /p/run4.sh 2>&1 | tee -a /out/all.log
RUN ls -la /out; echo IMAGE-DONE
