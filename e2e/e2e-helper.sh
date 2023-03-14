#!/bin/bash

log() {
    printf "\\033[1;33m%s\\033[0m\\n" "$*"
}

ok() {
    printf "\\033[1;32m%s\\033[0m\\n" "$*"
}

err() {
    printf "\\033[1;31m%s\\033[0m\\n" "$*"
}

exec_on_host() {
    local retval=0
    for i in $(seq 1 30); do
        kubectl exec $(kubectl get pod -l app=debug -o jsonpath="{.items[0].metadata.name}") -- bash -c "nsenter -t 1 -m bash -c \"$1\"" > $2 || retval=$?
        if [ "$retval" -ne 0 ]; then
            sleep 10
            continue
        fi
        break
    done
}

addJsonToFile() {
    k=$1; v=$2
    jq -r --arg key $k --arg value $v '. + { ($key) : $value}' < fields.json > dummy.json && mv dummy.json fields.json
}

getAgentPoolProfileValues() {
    declare -a properties=("mode" "name" "nodeImageVersion")

    for property in "${properties[@]}"; do
        value=$(jq -r .agentPoolProfiles[].${property} < cluster_info.json)
        addJsonToFile $property $value
    done
}

getFQDN() {
    fqdn=$(jq -r '.fqdn' < cluster_info.json)
    addJsonToFile "fqdn" $fqdn
}

getMSIResourceID() {
    msiResourceID=$(jq -r '.identityProfile.kubeletidentity.resourceId' < cluster_info.json)
    addJsonToFile "msiResourceID" $msiResourceID
}

getTenantID() {
    tenantID=$(jq -r '.identity.tenantId' < cluster_info.json)
    addJsonToFile "tenantID" $tenantID
}