package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/Azure/agentbaker/pkg/agent/datamodel"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/sanity-io/litter"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"
)

func nsenterCommandArray() []string {
	return []string{
		"nsenter",
		"-t",
		"1",
		"-m",
		"bash",
		"-c",
	}
}

const notAnSshKey = `LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUJsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFZRUF0UkJFMDBPTzBQVllRQUxZd20rMzQzSWoxTmZpWG9hSUhWd3EraDRURmh5MWhuSW9nb0lrCnMrUXBoZ1FYRlVoeVZ5Z1dqM2F0UW5CaGZLazRqK3d1OERNcVBsc0huZzFhNWtzNzZVQ3YwUVRhK3lUdlZMZ09LSUxzUWgKakxVYUhQUUpPREJQSWZOUHFFcEIzYklJc1czTW5sMUtjM1lUdFhING5iVmxzM3MxaUNpRU15TU9jSUVvWnhjT0k2dFVadwpEUjlBcy9HbWczUnVVbVRvdWZ6Z3FHNWxIUzdrRElyNnJPdmp3TmQvb3VnR2JYRFU4Ky9hUzVDV2I2RlAxR1ExTlk2Wmk4CjZqWTlTMTkwWmUwM2x5Q1FJK1VjMjNXb0FCajJaRGtEUU1vcWNYc3J0cUlyQmwzdHFGTlNHU1c4czMrbFVCaTMzTzBQaUwKUG1pdDNPNG5kT0d3UGpsODUxdGMyQXVVdVFCWGNzdGJBVFRJTWd1eUYvcUpLTzNuTTFuVTFSOTR4YTNFR2pCL3hYOFRLRQp6emx3WnZNTCtzVkZhYkNpaWQybVpjN0JyQytMbEVSZndkcU1NbmFlNnNlNzU1cW9wdGlQRm1hQzNUR3IzQzlMZFpZRWZLCm50MVBYQitLcDJxL1AzRnVuMEhiN2dXc3dkLy85MGJYODhlcXlhRnRBQUFGbU5JSHloZlNCOG9YQUFBQUIzTnphQzF5YzIKRUFBQUdCQUxVUVJOTkRqdEQxV0VBQzJNSnZ0K055STlUWDRsNkdpQjFjS3ZvZUV4WWN0WVp5S0lLQ0pMUGtLWVlFRnhWSQpjbGNvRm85MnJVSndZWHlwT0kvc0x2QXpLajViQjU0Tld1WkxPK2xBcjlFRTJ2c2s3MVM0RGlpQzdFSVl5MUdoejBDVGd3ClR5SHpUNmhLUWQyeUNMRnR6SjVkU25OMkU3VngrSjIxWmJON05ZZ29oRE1qRG5DQktHY1hEaU9yVkdjQTBmUUxQeHBvTjAKYmxKazZMbjg0S2h1WlIwdTVBeUsrcXpyNDhEWGY2TG9CbTF3MVBQdjJrdVFsbStoVDlSa05UV09tWXZPbzJQVXRmZEdYdApONWNna0NQbEhOdDFxQUFZOW1RNUEwREtLbkY3SzdhaUt3WmQ3YWhUVWhrbHZMTi9wVkFZdDl6dEQ0aXo1b3JkenVKM1RoCnNENDVmT2RiWE5nTGxMa0FWM0xMV3dFMHlESUxzaGY2aVNqdDV6TloxTlVmZU1XdHhCb3dmOFYvRXloTTg1Y0diekMvckYKUldtd29vbmRwbVhPd2F3dmk1UkVYOEhhakRKMm51ckh1K2VhcUtiWWp4Wm1ndDB4cTl3dlMzV1dCSHlwN2RUMXdmaXFkcQp2ejl4YnA5QjIrNEZyTUhmLy9kRzEvUEhxc21oYlFBQUFBTUJBQUVBQUFHQkFJVWlra2o1cXdEUTluUVM0OG1NbGgxQzV6Ci94QWIxWmxLcHFCQnZuazBjMkV1L3A3d21Qb21jNEJLUkxTNkhWcEdXYno0THIwNWcveEI4QzJ0bFE1RzZ3WUlaN0xzMnoKcWp3ZDQ4NnVSdGtkaGRzWEhIZ2g0aDg5clhVb2dBL2xOOXlXMnNiL05aMGgrL2dsRCtRTkFlR1UvMDd2S1pSd0txN0JFaQp1Y1pRZVZ0RjEzYzJkcjZZNmRscnBYVHEzT1BrUVh6OTdBZUJ5K3R3UVV1TjlSSnV3U1NIMDk1bWVtcFk0UzRXUUIwUk03CklzYkVLWUc0d3IyL2NpNWc0YThkZ3BsRnIzUHlGb2tVRTFOQzExZDYvRlMrL2c3U05GOXBNWXE0b2RHZHkrKzJDRmc0S1IKa1duOHdVb0paV2h3YzNnQ0RlYnhBZmdWd3V6NXE5WldWMW1SRWt0VmhUZGY3dGJQeU92YjM2NjU1eWMycUhON1Z3T3h5ZwpERFJPWUkvaEVlUUcwdFFTQ2NxZHlqczFnVU9lL2owNUZCUFkzaXh3Qzh4RG5YVXVPOURjbG9RNVptT3JmRUhhRW8yYmRSCk1rNWNraGJTd21uNlU5Qmp3Q04rbENxK1hrT1d6L2ZOcms3Mm1IY2FQTWt4WmxKelpCNGNBOTBkaHg3YXpQd0ZmS1FRQUEKQU1BdklPZk8wMVVpRjdPS05xSHdaV0txU2VkVVRUa2hqd2RzdmZ5bzg0bDViQWZDVTVRRVNkbzdBOGlSZUhpUW5ZckQ5ZwpuR2IrNEJrZDI4S1E1UkxOb1lxZDgrK2xhQWUyNE1SVFFPc3psUS9LK3RRWWdWazBOaTRjeFhsWFc1TzVyTEFTbEw3THQ5CmorbzJiQkluSWs2TThZYStnRFJrWWtmYXhIWENoK0FxOUxXNEF4bHhJZEc2SzRQOXlYcUhGakNyMVRvNGk2NUtHUkQ1Wm4KNDFVR1paVUpWakZBL0E3SUM2KzVlSDZQSkE4MUk3VER2Tmt0WGQ0VGhQRTd5S2lCMEFBQURCQU9VWGU2b2JGWk13NjFMUgozVE84NFd4Q09TUjgvamNIRDNxSHRKdFdMakkvYk53MGthQVhOMUpsdHFiTElBL08ydFdPY2ZEeEpFYU1sQjRUcmdZV0FUCnI1VkZFV1hZS0MySGxSVGEva2c3QS9HUk9Od1hIS2V5dXlscFVNN0N6MTdMa2k5ZTF5QkVOYTRGQmg4V3c3VGtjaGtrVDcKc3dsbEh3QlI3dGlTWlBEZXl2UzZqZUo3OWxwNlFGMTc3NTZmdHg1RjAxbDZVV3hUYmlPSndiU3FxZUxQS1E5SldnRWRTQwp2MjNzcTNQV1F2Q1ZiSWtkOS9YK1piWVFCTzhOUWYvUUFBQU1FQXlsU2lvclF4dDlQY2ljTy9taXJjdlpzTC9tdldORy95ClY1L1BoRml3WTJ2c0d1RUFSYkxFWEQvSkVDck5rM3VZS0VZRnFKZXRIbTl6ajdlcWlJSHFWemtHaU13ZE9zNXZQM25sREsKK05PWjFiNG9rVzgwdjRJWWduZ2pqN1B5a2kreUxMQzlnZS9lQ3NhM1pvNDNMUTNoQXNhcFZ6N3YxUnYvMFAzcGVteW8zdgo5K0lUUlVTdnpuaTd2bGIxK0JIMzBMdTNOWm9pWmZ4K0JpMHJFU1lBN29qaXFjK21SZG5BT3Q3UWw0QlJ4N1BZRWkyWkdKCk8xZ0JLWnY2OFRzQ294QUFBQUlYSnZiM1JBVldKMWJuUjFMVEl3TURRdFptOWpZV3d0TmpRdGJXbHVhVzFoYkFFPQotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K`
const sshCommandTemplate = `echo %s | base64 -d > sshkey && chmod 0600 sshkey && ssh -i sshkey -o PasswordAuthentication=no -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=5 azureuser@%s sudo`

func extractLogsFromFailedVM(ctx context.Context, t *testing.T, cloud *azureClient, kube *kubeclient, subscription, resourceGroupName, clusterName, vmssName string) (map[string]string, error) {
	pl := cloud.coreClient.Pipeline()
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachineScaleSets/%s/virtualMachines/%d/networkInterfaces?api-version=2018-10-01",
		subscription,
		"MC_agentbaker-e2e-tests_agentbaker-e2e-test-cluster_eastus",
		vmssName,
		0,
	)
	req, err := runtime.NewRequest(ctx, "GET", url)
	if err != nil {
		return nil, err
	}

	resp, err := pl.Do(req)
	if err != nil {
		return nil, err
	}

	// 	ctx,
	// 	"MC_agentbaker-e2e-tests_agentbaker-e2e-test-cluster_eastus",
	// 	"Microsoft.Compute",
	// 	"/virtualMachineScaleSets/"+vmssName+"/virtualMachines",
	// 	"0",
	// 	"networkInterfaces",
	// 	"2018-10-01",
	// 	nil,
	// )
	if err != nil {
		return nil, err
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var instanceNICResult listVMSSVMNetworkInterfaceResult

	if err := json.Unmarshal(respBytes, &instanceNICResult); err != nil {
		return nil, err
	}

	privateIP := instanceNICResult.Value[0].Properties.IPConfigurations[0].Properties.PrivateIPAddress

	sshCommand := fmt.Sprintf(sshCommandTemplate, notAnSshKey, privateIP)

	commandList := map[string]string{
		"/var/log/azure/cluster-provision/log": "cat /var/log/azure/cluster-provision.log",
	}

	podList := corev1.PodList{}
	if err := kube.dynamic.List(context.Background(), &podList, client.MatchingLabels{"app": "debug"}); err != nil {
		return nil, fmt.Errorf("failed to list debug pod: %q", err)
	}

	if len(podList.Items) < 1 {
		return nil, fmt.Errorf("failed to find debug pod, list by selector returned no results")
	}

	podName := podList.Items[0].ObjectMeta.Name

	var result = map[string]string{}
	for file, sourceCmd := range commandList {
		mergedCmd := fmt.Sprintf("%s %s", sshCommand, sourceCmd)
		cmd := append(nsenterCommandArray(), mergedCmd)

		req := kube.typed.CoreV1().RESTClient().Post().Resource("pods").Name(podName).Namespace("default").SubResource("exec")

		option := &corev1.PodExecOptions{
			Command: cmd,
			Stdout:  true,
			Stderr:  true,
		}

		req.VersionedParams(
			option,
			scheme.ParameterCodec,
		)

		exec, err := remotecommand.NewSPDYExecutor(kube.rest, "POST", req.URL())
		if err != nil {
			return nil, err
		}

		var stdout, stderr bytes.Buffer

		err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: &stdout,
			Stderr: &stderr,
		})

		t.Log("stdout")
		t.Log(stdout.String())

		t.Log("stderr")
		t.Log(stderr.String())

		if err != nil {
			return nil, err
		}

		result[file] = stdout.String()
	}

	litter.Dump(result)

	return result, nil
}

func extractClusterParameters(ctx context.Context, t *testing.T, kube *kubeclient) (map[string]string, error) {
	commandList := map[string]string{
		"/etc/kubernetes/azure.json":            "cat /etc/kubernetes/azure.json",
		"/etc/kubernetes/certs/ca.crt":          "cat /etc/kubernetes/certs/ca.crt",
		"/var/lib/kubelet/bootstrap-kubeconfig": "cat /var/lib/kubelet/bootstrap-kubeconfig",
	}

	podList := corev1.PodList{}
	if err := kube.dynamic.List(context.Background(), &podList, client.MatchingLabels{"app": "debug"}); err != nil {
		return nil, fmt.Errorf("failed to list debug pod: %q", err)
	}

	if len(podList.Items) < 1 {
		return nil, fmt.Errorf("failed to find debug pod, list by selector returned no results")
	}

	podName := podList.Items[0].ObjectMeta.Name

	var result = map[string]string{}
	for file, sourceCmd := range commandList {
		cmd := append(nsenterCommandArray(), sourceCmd)

		req := kube.typed.CoreV1().RESTClient().Post().Resource("pods").Name(podName).Namespace("default").SubResource("exec")

		option := &corev1.PodExecOptions{
			Command: cmd,
			Stdout:  true,
			Stderr:  true,
		}

		req.VersionedParams(
			option,
			scheme.ParameterCodec,
		)

		exec, err := remotecommand.NewSPDYExecutor(kube.rest, "POST", req.URL())
		if err != nil {
			return nil, err
		}

		var stdout, stderr bytes.Buffer

		err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: &stdout,
			Stderr: &stderr,
		})

		if err != nil {
			return nil, err
		}

		result[file] = stdout.String()
	}

	return result, nil
}

func ensureDebugDaemonset(ctx context.Context, kube *kubeclient, resourceGroupName, clusterName string) error {
	manifest := getDebugDaemonset()
	var ds appsv1.DaemonSet

	if err := yaml.Unmarshal([]byte(manifest), &ds); err != nil {
		return fmt.Errorf("failed to unmarshal debug daemonset manifest: %q", err)
	}

	desired := ds.DeepCopy()
	_, err := controllerutil.CreateOrUpdate(ctx, kube.dynamic, &ds, func() error {
		ds = *desired
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to apply debug daemonset: %q", err)
	}

	return nil
}

func getBaseBootstrappingConfig(ctx context.Context, t *testing.T, cloud *azureClient, suiteConfig *suiteConfig, clusterParams map[string]string) (*datamodel.NodeBootstrappingConfiguration, error) {
	nbc := baseTemplate()
	nbc.ContainerService.Properties.CertificateProfile.CaCertificate = clusterParams["/etc/kubernetes/certs/ca.crt"]

	bootstrapKubeconfig := clusterParams["/var/lib/kubelet/bootstrap-kubeconfig"]

	bootstrapToken, err := extractKeyValuePair("token", bootstrapKubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to extract bootstrap token via regex: %q", err)
	}

	bootstrapToken, err = strconv.Unquote(bootstrapToken)
	if err != nil {
		return nil, fmt.Errorf("failed to unquote bootstrap token: %q", err)
	}

	server, err := extractKeyValuePair("server", bootstrapKubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to extract fqdn via regex: %q", err)
	}
	tokens := strings.Split(server, ":")
	if len(tokens) != 3 {
		return nil, fmt.Errorf("expected 3 tokens from fqdn %q, got %d", server, len(tokens))
	}
	// strip off the // prefix from https://
	fqdn := tokens[1][2:]

	nbc.KubeletClientTLSBootstrapToken = &bootstrapToken
	nbc.ContainerService.Properties.HostedMasterProfile.FQDN = fqdn

	return nbc, nil
}
