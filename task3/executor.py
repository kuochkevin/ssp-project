from transformers import pipeline
import torch
import os
import re
import pandas as pd
import subprocess
import json

KUBESCAPE_CONTROLS = [
    "C-0001: Forbidden Container Registries",
    "C-0002: Prevent containers from allowing command execution",
    "C-0004: Resources memory limit and request",
    "C-0005: API server insecure port is enabled",
    "C-0007: Roles with delete capabilities",
    "C-0009: Resource limits",
    "C-0012: Applications credentials in configuration files",
    "C-0013: Non-root containers",
    "C-0014: Access Kubernetes dashboard",
    "C-0015: List Kubernetes secrets",
    "C-0016: Allow privilege escalation",
    "C-0017: Immutable container filesystem",
    "C-0018: Configured readiness probe",
    "C-0020: Mount service principal",
    "C-0021: Exposed sensitive interfaces",
    "C-0026: Kubernetes CronJob",
    "C-0030: Ingress and Egress blocked",
    "C-0031: Delete Kubernetes events",
    "C-0034: Automatic mapping of service account",
    "C-0035: Administrative Roles",
    "C-0036: Validate admission controller (validating)",
    "C-0037: CoreDNS poisoning",
    "C-0038: Host PID/IPC privileges",
    "C-0039: Validate admission controller (mutating)",
    "C-0041: HostNetwork access",
    "C-0042: SSH server running inside container",
    "C-0044: Container hostPort",
    "C-0045: Writable hostPath mount",
    "C-0046: Insecure capabilities",
    "C-0048: HostPath mount",
    "C-0049: Network mapping",
    "C-0050: Resources CPU limit and request",
    "C-0052: Instance Metadata API",
    "C-0053: Access container service account",
    "C-0054: Cluster internal networking",
    "C-0055: Linux hardening",
    "C-0056: Configured liveness probe",
    "C-0057: Privileged container",
    "C-0058: CVE-2021-25741 - Using symlink for arbitrary host file system access",
    "C-0059: CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability",
    "C-0061: Pods in default namespace",
    "C-0062: Sudo in container entrypoint",
    "C-0063: Portforwarding privileges",
    "C-0065: No impersonation",
    "C-0066: Secret/etcd encryption enabled",
    "C-0067: Audit logs enabled",
    "C-0068: PSP enabled",
    "C-0069: Disable anonymous access to Kubelet service",
    "C-0070: Enforce Kubelet client TLS authentication",
    "C-0073: Naked pods",
    "C-0074: Container runtime socket mounted",
    "C-0075: Image pull policy on latest tag",
    "C-0076: Label usage for resources",
    "C-0077: K8s common labels usage",
    "C-0078: Images from allowed registry",
    "C-0079: CVE-2022-0185-linux-kernel-container-escape",
    "C-0081: CVE-2022-24348-argocddirtraversal",
    "C-0083: Workloads with Critical vulnerabilities exposed to external traffic",
    "C-0084: Workloads with RCE vulnerabilities exposed to external traffic",
    "C-0085: Workloads with excessive amount of vulnerabilities",
    "C-0087: CVE-2022-23648-containerd-fs-escape",
    "C-0088: RBAC enabled",
    "C-0089: CVE-2022-3172-aggregated-API-server-redirect",
    "C-0090: CVE-2022-39328-grafana-auth-bypass",
    "C-0091: CVE-2022-47633-kyverno-signature-bypass",
    "C-0092: Ensure that the API server pod specification file permissions are set to 600 or more restrictive",
    "C-0093: Ensure that the API server pod specification file ownership is set to root:root",
    "C-0094: Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive",
    "C-0095: Ensure that the controller manager pod specification file ownership is set to root:root",
    "C-0096: Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive",
    "C-0097: Ensure that the scheduler pod specification file ownership is set to root:root",
    "C-0098: Ensure that the etcd pod specification file permissions are set to 600 or more restrictive",
    "C-0099: Ensure that the etcd pod specification file ownership is set to root:root",
    "C-0100: Ensure that the Container Network Interface file permissions are set to 600 or more restrictive",
    "C-0101: Ensure that the Container Network Interface file ownership is set to root:root",
    "C-0102: Ensure that the etcd data directory permissions are set to 700 or more restrictive",
    "C-0103: Ensure that the etcd data directory ownership is set to etcd:etcd",
    "C-0104: Ensure that the admin.conf file permissions are set to 600",
    "C-0105: Ensure that the admin.conf file ownership is set to root:root",
    "C-0106: Ensure that the scheduler.conf file permissions are set to 600 or more restrictive",
    "C-0107: Ensure that the scheduler.conf file ownership is set to root:root",
    "C-0108: Ensure that the controller-manager.conf file permissions are set to 600 or more restrictive",
    "C-0109: Ensure that the controller-manager.conf file ownership is set to root:root",
    "C-0110: Ensure that the Kubernetes PKI directory and file ownership is set to root:root",
    "C-0111: Ensure that the Kubernetes PKI certificate file permissions are set to 600 or more restrictive",
    "C-0112: Ensure that the Kubernetes PKI key file permissions are set to 600",
    "C-0113: Ensure that the API Server --anonymous-auth argument is set to false",
    "C-0114: Ensure that the API Server --token-auth-file parameter is not set",
    "C-0115: Ensure that the API Server --DenyServiceExternalIPs is not set",
    "C-0116: Ensure that the API Server --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
    "C-0117: Ensure that the API Server --kubelet-certificate-authority argument is set as appropriate",
    "C-0118: Ensure that the API Server --authorization-mode argument is not set to AlwaysAllow",
    "C-0119: Ensure that the API Server --authorization-mode argument includes Node",
    "C-0120: Ensure that the API Server --authorization-mode argument includes RBAC",
    "C-0121: Ensure that the admission control plugin EventRateLimit is set",
    "C-0122: Ensure that the admission control plugin AlwaysAdmit is not set",
    "C-0123: Ensure that the admission control plugin AlwaysPullImages is set",
    "C-0124: Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used",
    "C-0125: Ensure that the admission control plugin ServiceAccount is set",
    "C-0126: Ensure that the admission control plugin NamespaceLifecycle is set",
    "C-0127: Ensure that the admission control plugin NodeRestriction is set",
    "C-0128: Ensure that the API Server --secure-port argument is not set to 0",
    "C-0129: Ensure that the API Server --profiling argument is set to false",
    "C-0130: Ensure that the API Server --audit-log-path argument is set",
    "C-0131: Ensure that the API Server --audit-log-maxage argument is set to 30 or as appropriate",
    "C-0132: Ensure that the API Server --audit-log-maxbackup argument is set to 10 or as appropriate",
    "C-0133: Ensure that the API Server --audit-log-maxsize argument is set to 100 or as appropriate",
    "C-0134: Ensure that the API Server --request-timeout argument is set as appropriate",
    "C-0135: Ensure that the API Server --service-account-lookup argument is set to true",
    "C-0136: Ensure that the API Server --service-account-key-file argument is set as appropriate",
    "C-0137: Ensure that the API Server --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
    "C-0138: Ensure that the API Server --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
    "C-0139: Ensure that the API Server --client-ca-file argument is set as appropriate",
    "C-0140: Ensure that the API Server --etcd-cafile argument is set as appropriate",
    "C-0141: Ensure that the API Server --encryption-provider-config argument is set as appropriate",
    "C-0142: Ensure that encryption providers are appropriately configured",
    "C-0143: Ensure that the API Server only makes use of Strong Cryptographic Ciphers",
    "C-0144: Ensure that the Controller Manager --terminated-pod-gc-threshold argument is set as appropriate",
    "C-0145: Ensure that the Controller Manager --profiling argument is set to false",
    "C-0146: Ensure that the Controller Manager --use-service-account-credentials argument is set to true",
    "C-0147: Ensure that the Controller Manager --service-account-private-key-file argument is set as appropriate",
    "C-0148: Ensure that the Controller Manager --root-ca-file argument is set as appropriate",
    "C-0149: Ensure that the Controller Manager RotateKubeletServerCertificate argument is set to true",
    "C-0150: Ensure that the Controller Manager --bind-address argument is set to 127.0.0.1",
    "C-0151: Ensure that the Scheduler --profiling argument is set to false",
    "C-0152: Ensure that the Scheduler --bind-address argument is set to 127.0.0.1",
    "C-0153: Ensure that the --cert-file and --key-file arguments are set as appropriate",
    "C-0154: Ensure that the --client-cert-auth argument is set to true",
    "C-0155: Ensure that the --auto-tls argument is not set to true",
    "C-0156: Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate",
    "C-0157: Ensure that the --peer-client-cert-auth argument is set to true",
    "C-0158: Ensure that the --peer-auto-tls argument is not set to true",
    "C-0159: Ensure that a unique Certificate Authority is used for etcd",
    "C-0160: Ensure that a minimal audit policy is created",
    "C-0161: Ensure that the audit policy covers key security concerns",
    "C-0162: Ensure that the kubelet service file permissions are set to 600 or more restrictive",
    "C-0163: Ensure that the kubelet service file ownership is set to root:root",
    "C-0164: If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive",
    "C-0165: If proxy kubeconfig file exists ensure ownership is set to root:root",
    "C-0166: Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive",
    "C-0167: Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root",
    "C-0168: Ensure that the certificate authorities file permissions are set to 600 or more restrictive",
    "C-0169: Ensure that the client certificate authorities file ownership is set to root:root",
    "C-0170: If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive",
    "C-0171: If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root",
    "C-0172: Ensure that the --anonymous-auth argument is set to false",
    "C-0173: Ensure that the --authorization-mode argument is not set to AlwaysAllow",
    "C-0174: Ensure that the --client-ca-file argument is set as appropriate",
    "C-0175: Verify that the --read-only-port argument is set to 0",
    "C-0176: Ensure that the --streaming-connection-idle-timeout argument is not set to 0",
    "C-0177: Ensure that the --protect-kernel-defaults argument is set to true",
    "C-0178: Ensure that the --make-iptables-util-chains argument is set to true",
    "C-0179: Ensure that the --hostname-override argument is not set",
    "C-0180: Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture",
    "C-0181: Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
    "C-0182: Ensure that the --rotate-certificates argument is not set to false",
    "C-0183: Verify that the RotateKubeletServerCertificate argument is set to true",
    "C-0184: Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers",
    "C-0185: Ensure that the cluster-admin role is only used where required",
    "C-0186: Minimize access to secrets",
    "C-0187: Minimize wildcard use in Roles and ClusterRoles",
    "C-0188: Minimize access to create pods",
    "C-0189: Ensure that default service accounts are not actively used",
    "C-0190: Ensure that Service Account Tokens are only mounted where necessary",
    "C-0191: Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster",
    "C-0192: Ensure that the cluster has at least one active policy control mechanism in place",
    "C-0193: Minimize the admission of privileged containers",
    "C-0194: Minimize the admission of containers wishing to share the host process ID namespace",
    "C-0195: Minimize the admission of containers wishing to share the host IPC namespace",
    "C-0196: Minimize the admission of containers wishing to share the host network namespace",
    "C-0197: Minimize the admission of containers with allowPrivilegeEscalation",
    "C-0198: Minimize the admission of root containers",
    "C-0199: Minimize the admission of containers with the NET_RAW capability",
    "C-0200: Minimize the admission of containers with added capabilities",
    "C-0201: Minimize the admission of containers with capabilities assigned",
    "C-0202: Minimize the admission of Windows HostProcess Containers",
    "C-0203: Minimize the admission of HostPath volumes",
    "C-0204: Minimize the admission of containers which use HostPorts",
    "C-0205: Ensure that the CNI in use supports Network Policies",
    "C-0206: Ensure that all Namespaces have Network Policies defined",
    "C-0207: Prefer using secrets as files over secrets as environment variables",
    "C-0208: Consider external secret storage",
    "C-0209: Create administrative boundaries between resources using namespaces",
    "C-0210: Ensure that the seccomp profile is set to docker/default in your pod definitions",
    "C-0211: Apply Security Context to Your Pods and Containers",
    "C-0212: The default namespace should not be used",
    "C-0213: Minimize the admission of privileged containers",
    "C-0214: Minimize the admission of containers wishing to share the host process ID namespace",
    "C-0215: Minimize the admission of containers wishing to share the host IPC namespace",
    "C-0216: Minimize the admission of containers wishing to share the host network namespace",
    "C-0217: Minimize the admission of containers with allowPrivilegeEscalation",
    "C-0218: Minimize the admission of root containers",
    "C-0219: Minimize the admission of containers with added capabilities",
    "C-0220: Minimize the admission of containers with capabilities assigned",
    "C-0221: Ensure Image Vulnerability Scanning using Amazon ECR image scanning or a third party provider",
    "C-0222: Minimize user access to Amazon ECR",
    "C-0223: Minimize cluster access to read-only for Amazon ECR",
    "C-0225: Prefer using dedicated EKS Service Accounts",
    "C-0226: Prefer using a container-optimized OS when possible",
    "C-0227: Restrict Access to the Control Plane Endpoint",
    "C-0228: Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled",
    "C-0229: Ensure clusters are created with Private Nodes",
    "C-0230: Ensure Network Policy is Enabled and set as appropriate",
    "C-0231: Encrypt traffic to HTTPS load balancers with TLS certificates",
    "C-0232: Manage Kubernetes RBAC users with AWS IAM Authenticator for Kubernetes or Upgrade to AWS CLI v1.16.156",
    "C-0233: Consider Fargate for running untrusted workloads",
    "C-0234: Consider external secret storage",
    "C-0235: Ensure that the kubelet configuration file has permissions set to 644 or more restrictive",
    "C-0236: Verify image signature",
    "C-0237: Check if signature exists",
    "C-0238: Ensure that the kubeconfig file permissions are set to 644 or more restrictive",
    "C-0239: Prefer using dedicated AKS Service Accounts",
    "C-0240: Ensure Network Policy is Enabled and set as appropriate",
    "C-0241: Use Azure RBAC for Kubernetes Authorization",
    "C-0242: Hostile multi-tenant workloads",
    "C-0243: Ensure Image Vulnerability Scanning using Azure Defender image scanning or a third party provider",
    "C-0244: Ensure Kubernetes Secrets are encrypted",
    "C-0245: Encrypt traffic to HTTPS load balancers with TLS certificates",
    "C-0246: Avoid use of system:masters group",
    "C-0247: Restrict Access to the Control Plane Endpoint",
    "C-0248: Ensure clusters are created with Private Nodes",
    "C-0250: Minimize cluster access to read-only for Azure Container Registry (ACR)",
    "C-0251: Minimize user access to Azure Container Registry (ACR)",
    "C-0252: Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled",
    "C-0253: Deprecated Kubernetes image registry",
    "C-0254: Enable audit Logs",
    "C-0255: Workload with secret access",
    "C-0256: External facing",
    "C-0257: Workload with PVC access",
    "C-0258: Workload with ConfigMap access",
    "C-0259: Workload with credential access",
    "C-0260: Missing network policy",
    "C-0261: ServiceAccount token mounted",
    "C-0262: Anonymous user has RoleBinding",
    "C-0263: Ingress uses TLS",
    "C-0264: PersistentVolume without encryption",
    "C-0265: system:authenticated user has elevated roles",
    "C-0266: Exposure to internet via Gateway API or Istio Ingress",
    "C-0267: Workload with cluster takeover roles",
    "C-0268: Ensure CPU requests are set",
    "C-0269: Ensure memory requests are set",
    "C-0270: Ensure CPU limits are set",
    "C-0271: Ensure memory limits are set",
    "C-0272: Workload with administrative roles",
    "C-0273: Outdated Kubernetes version",
    "C-0274: Verify Authenticated Service",
    "C-0275: Minimize the admission of containers wishing to share the host process ID namespace",
    "C-0276: Minimize the admission of containers wishing to share the host IPC namespace",
    "C-0277: Ensure that the API Server only makes use of Strong Cryptographic Ciphers",
    "C-0278: Minimize access to create persistent volumes",
    "C-0279: Minimize access to the proxy sub-resource of nodes",
    "C-0280: Minimize access to the approval sub-resource of certificatesigningrequests objects",
    "C-0281: Minimize access to webhook configuration objects",
    "C-0282: Minimize access to the service account token creation",
    "C-0283: Ensure that the API Server --DenyServiceExternalIPs is set",
    "C-0284: Ensure that the Kubelet is configured to limit pod PIDS",
]


def load_inputs(names_path="unique_names.txt", entries_path="unique_entries.txt"):
    if not os.path.exists(names_path):
        raise FileNotFoundError("unique_names.txt does not exist.")
    elif not os.path.exists(entries_path):
        raise FileNotFoundError("unique_entries.txt does not exist.")
    with open(names_path, "r") as f:
        names = f.readlines()
    with open(entries_path, "r") as f:
        entries = f.readlines()
    return names, entries


def load_gemma():
    pipe = pipeline(
        "text-generation",
        model="google/gemma-3-1b-it",
        device=0 if torch.cuda.is_available() else -1,
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
    )
    return pipe


def get_controls(names, entries, pipe):
    # Collect unique KDE names from both files, avoiding duplicates
    seen = set()
    data = []

    if names[0].strip() != "NO DIFFERENCES IN REGARDS TO ELEMENT NAMES":
        for line in names:
            name = line.strip()
            if name and name not in seen:
                seen.add(name)
                data.append(name)

    if entries[0].strip() != "NO DIFFERENCES IN REGARDS TO ELEMENT REQUIREMENTS":
        for line in entries:
            # Column 0 is the KDE name; collect unique names not already added
            name = line.split(',')[0].strip()
            if name and name not in seen:
                seen.add(name)
                data.append(name)

    if not data:
        with open("controls.txt", "w") as f:
            f.write("NO DIFFERENCES FOUND")
        return "NO DIFFERENCES FOUND"

    prompt = f"""
    You are a Kubernetes security expert.
    Given these KDE names:
    {data}
    Map them to the most relevant controls from this list:
    {KUBESCAPE_CONTROLS}
    Reply with ONLY a comma-separated list of control IDs like: C-0057,C-0066,C-0067
    No explanation. No extra text. Only control IDs."""

    messages = [{"role": "user", "content": prompt}]
    output = pipe(messages, max_new_tokens=256, do_sample=False)

    # Chat format returns the last message content
    raw = output[0]["generated_text"][-1]["content"].strip()
    print("=== LLM RAW RESPONSE ===")
    print(repr(raw))

    valid_ids = {c.split(":")[0].strip() for c in KUBESCAPE_CONTROLS}
    extracted_ids = re.findall(r'C-\d+', raw)
    control_ids = list({cid for cid in extracted_ids if cid in valid_ids})

    if not control_ids:
        result = "NO DIFFERENCES FOUND"
    else:
        result = ",".join(control_ids)

    with open("controls.txt", "w") as f:
        f.write(result)
    return result


def execute_kubescape(controls_file: str, yamls_dir: str) -> pd.DataFrame:
    with open(controls_file, "r") as f:
        content = f.read().strip()

    if content == "NO DIFFERENCES FOUND":
        cmd = ["kubescape", "scan", yamls_dir, "--format", "json", "--output", "kubescape_results.json"]
    else:
        control_ids = content.strip()
        cmd = ["kubescape", "scan", "control", control_ids, yamls_dir, "--format", "json", "--output", "kubescape_results.json"]

    subprocess.run(cmd, capture_output=True, text=True)

    with open("kubescape_results.json", "r") as f:
        data = json.load(f)

    # Get control-level summary from summaryDetails
    controls_summary = data.get("summaryDetails", {}).get("controls", {})

    rows = []
    for resource in data.get("results", []):
        for control in resource.get("controls", []):
            control_id = control.get("controlID", "")
            summary = controls_summary.get(control_id, {})
            rows.append({
                "FilePath": yamls_dir,
                "Severity": summary.get("severity", ""),
                "Control name": control.get("name", ""),
                "Failed resources": summary.get("ResourceCounters", {}).get("failedResources", 0),
                "All Resources": (
                    summary.get("ResourceCounters", {}).get("passedResources", 0) +
                    summary.get("ResourceCounters", {}).get("failedResources", 0) +
                    summary.get("ResourceCounters", {}).get("skippedResources", 0)
                ),
                "Compliance score": f"{round(summary.get('complianceScore', 0), 2)}%",
            })

    df = pd.DataFrame(rows, columns=["FilePath", "Severity", "Control name", "Failed resources", "All Resources", "Compliance score"])
    return df


def generate_csv(df: pd.DataFrame, output_path: str = "kubescape_results.csv") -> str:
    df.to_csv(output_path, index=False)
    return output_path


if __name__ == "__main__":
    names, entries = load_inputs()
    pipe = load_gemma()
    result = get_controls(names, entries, pipe)
    df = execute_kubescape("controls.txt", "YAMLfiles")
    generate_csv(df)
