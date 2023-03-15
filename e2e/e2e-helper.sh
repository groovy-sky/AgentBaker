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
    kubectl exec $(kubectl get pod -l app=debug -o jsonpath="{.items[0].metadata.name}") -- bash -c "nsenter -t 1 -m bash -c \"$1\"" > $2
}

ecec_on_host_for_windows() {
    INSTANCE_ID="$(az vmss list-instances --name $VMSS_NAME -g $MC_RESOURCE_GROUP_NAME | jq -r '.[0].instanceId')"
    PRIVATE_IP="$(az vmss nic list-vm-nics --vmss-name $VMSS_NAME -g $MC_RESOURCE_GROUP_NAME --instance-id $INSTANCE_ID | jq -r .[0].ipConfigurations[0].privateIPAddress)"
    set +x
    SSH_KEY=$(cat ~/.ssh/id_rsa)
    SSH_OPTS="-o PasswordAuthentication=no -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=5"
    SSH_CMD="echo '$SSH_KEY' > sshkey && chmod 0600 sshkey && ssh -i sshkey $SSH_OPTS azureuser@$PRIVATE_IP sudo"
    exec_on_host "$SSH_CMD cat /etc/kubernetes/azure.json" fields.json
    exec_on_host "$SSH_CMD cat /etc/kubernetes/certs/apiserver.crt | base64 -w 0" apiserver.crt
    exec_on_host "$SSH_CMD cat /etc/kubernetes/certs/ca.crt | base64 -w 0" ca.crt
    exec_on_host "$SSH_CMD cat /etc/kubernetes/certs/client.key | base64 -w 0" client.key
    exec_on_host "$SSH_CMD cat /var/lib/kubelet/bootstrap-kubeconfig" bootstrap-kubeconfig
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