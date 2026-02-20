# Integrating Azure DevOps CI/CD with a private OpenStack-hosted Kubernetes cluster on a single public-IP VPS

## Executive summary

Your environment is effectively a **private cloud behind a single edge IP**: only the host VPS is internet-routable (`89.233.107.185`), while OpenStack tenant networks and Kubernetes node addresses are private (`10.0.0.xx`). Given this, the decisive CI/CD constraint is **network reachability**: Microsoft-hosted Azure Pipelines agents generally **cannot route to private tenant IP ranges**, so they cannot reliably manage OpenStack resources or reach the Kubernetes API. citeturn23search10turn23search2turn28view0

Recommended enterprise-grade integration pattern:

- Run Azure Pipelines jobs that touch OpenStack or Kubernetes on a **self-hosted agent placed inside the private tenant network** (preferred) or on the host VPS (acceptable only with strict hardening). Microsoft-hosted agents remain useful for “public-only” build/test stages. citeturn23search2turn23search10
- Manage OpenStack with **Terraform** using the OpenStack provider authenticated via **`clouds.yaml`** and ideally **Keystone application credentials** (instead of user passwords). citeturn7view0turn4search12turn5search6
- Bootstrap Kubernetes with **kubeadm** (cloud-init for prerequisites + pipeline-driven SSH orchestration). citeturn30search4turn30search0turn30search1
- Deploy to the cluster using Azure Pipelines **Kubernetes tasks** (kubectl/Helm/manifest tasks) driven by **Kubernetes service connections** and least-privilege RBAC per namespace (`dev`, `test`, `acc`). citeturn24search2turn29search0turn29search1
- For production hardening, prefer **GitOps**: push manifests to a Git repo (e.g., entity["company","GitLab","devops platform company"]), and let Argo CD auto-sync + self-heal—reducing long-lived cluster credentials in Azure DevOps. citeturn26view0turn12search1turn12search0

Deliverables generated for direct reuse:
- [Download the Markdown guide](sandbox:/mnt/data/AzureDevOps_OpenStack_K8s_Integration_SingleIP_Guide.md)
- [Download the Word document](sandbox:/mnt/data/AzureDevOps_OpenStack_K8s_Integration_SingleIP_Guide.docx)

Unspecified items (explicitly required to finalise automation): OpenStack Keystone `auth_url`, region(s), tenant/project scoping, OpenStack API reachability (host-only vs tenant network), image/flavour IDs, exact node IPs, and final domain/hostnames per environment. Where unknown, placeholders are used.

## Environment constraints and target topology

Your single-IP VPS topology implies:

- Public ingress is **only** via `89.233.107.185:80/443` (edge reverse proxy).
- OpenStack tenant ips and Kubernetes nodes are **private** (`10.0.0.xx`), not directly reachable from the internet.
- Kubernetes API should remain **private** (default TCP `6443`). citeturn28view0
- NodePort services use the default port range **30000–32767** and must be reachable from the reverse proxy edge (not from the whole internet). citeturn28view0

Clean networking topology:

```mermaid
flowchart TB
  Internet((Internet)) --> DNS[DNS A records -> 89.233.107.185]
  DNS --> EDGE[Host VPS (public)<br/>89.233.107.185:80/443]
  EDGE --> RP[Reverse proxy edge<br/>NGINX/Traefik<br/>TLS termination]

  subgraph OpenStackTenant[OpenStack tenant network<br/>10.0.0.0/24]
    CI[CI Utility VM<br/>self-hosted ADO agent]
    CP[K8s control plane VM<br/>API: 10.0.0.xx:6443]
    W1[K8s worker VM 1]
    W2[K8s worker VM 2 (optional)]
  end

  subgraph K8S[Kubernetes]
    IN[ingress-nginx<br/>Service=NodePort<br/>30080/30443]
    DEV[Namespace dev<br/>WP + PG]
    TEST[Namespace test<br/>WP + PG]
    ACC[Namespace acc<br/>WP + PG]
    CSI[Cinder CSI + StorageClass]
  end

  RP -->|proxy to NodePort| IN
  IN --> DEV & TEST & ACC

  CI -->|private routing| CP
  CI -->|private routing| W1
  CI -->|private routing| W2
  CSI -->|OpenStack API| OpenStackAPIs[(Keystone/Cinder)]
```

Pipeline flow (what runs where):

```mermaid
flowchart LR
  Dev[Developer commit/PR] --> ADO[Azure DevOps pipeline]

  ADO -->|Stages: lint/test| Hosted[Microsoft-hosted agent]
  ADO -->|Stages: infra/bootstrap/deploy| SelfHosted[Self-hosted agent<br/>inside 10.0.0.0/24]

  SelfHosted --> TF[Terraform apply (OpenStack)]
  TF --> VMs[Provision VMs + networking<br/>no public floating IPs]

  SelfHosted --> SSH[SSH bootstrap (kubeadm)]
  SSH --> K8sReady[Kubernetes ready]

  SelfHosted --> Deploy[kubectl/helm apply]
  Deploy --> Apps[dev/test/acc apps]

  ADO -->|GitOps option| GitCommit[Commit manifests]
  GitCommit --> Argo[Argo CD auto-sync + self-heal]
  Argo --> Apps
```

## Service connections and authentication

Azure Pipelines “service connections” are authenticated connections used by tasks at runtime. Creation flow is via **Project settings → Service connections → New service connection**. citeturn1search9turn10search1

### Requested comparison: service connections and auth options

| Scope | Connection type | Best for | Auth options | Recommendation |
|---|---|---|---|---|
| Reaching host VPS | SSH | running bootstrap commands, copying files | SSH private key | **Yes** (bastion/jump) citeturn9search0turn22search0 |
| Reaching Kubernetes | Kubernetes | kubectl/helm/manifest deploys | kubeconfig or ServiceAccount token | **Yes** (1 per namespace) citeturn24search2turn24search8 |
| Pulling secrets | Azure Resource Manager | Key Vault integration | service principal / managed identity | **Yes** (for Key Vault) citeturn11search2turn0search2 |
| Managing OpenStack | (no native type) | IaC via Terraform | clouds.yaml / OS_* / token / app creds | **Use Terraform + secrets**, don’t expose OpenStack APIs publicly citeturn7view0turn4search12 |
| “Generic” endpoints | Generic | edge cases only | arbitrary | Avoid unless unavoidable citeturn14view0 |

### SSH service connection (UI steps)

1. In Azure DevOps: **Project settings → Service connections → New service connection**. citeturn1search9  
2. Select **SSH**.  
3. Set:
   - Host name: `89.233.107.185`
   - Port: `22`
   - Username: (your VPS admin user)
   - Authentication method: **Private key** (recommended)
4. Name: `ssh-openstack-host`
5. After creation, configure service connection security so only intended pipelines can use it. citeturn29search4turn29search10

This service connection is consumed by:
- `SSH@0` (run remote commands) citeturn9search0
- `CopyFilesOverSSH@0` (copy files/artifacts over SSH) citeturn22search0

### Kubernetes service connection (UI steps with modern token guidance)

Because your cluster is private, focus on two points:
- the service connection stores credentials (kubeconfig or token)
- **the runtime agent must be able to reach the Kubernetes API server** (e.g. `https://10.0.0.11:6443`). citeturn24search2turn28view0

Recommended enterprise approach: create **three** Kubernetes service connections:
- `k8s-dev` scoped to namespace `dev`
- `k8s-test` scoped to namespace `test`
- `k8s-acc` scoped to namespace `acc`

Create Kubernetes RBAC (Role/RoleBinding) per namespace following least privilege. Kubernetes RBAC and RBAC good practices are explicitly recommended for least privilege. citeturn29search0turn29search1

ServiceAccount token approach (preferred for ADO tasks):
- Kubernetes can issue JWTs for ServiceAccounts; you can request tokens using `kubectl create token`. citeturn17search14turn27search0
- Many clusters no longer auto-create Secret-backed SA tokens; use TokenRequest (`kubectl create token`) or explicitly create a token Secret if a tool requires it. citeturn27search2turn27search0turn27search3

### Azure Key Vault integration (service connection + variable group)

If you choose Key Vault as the primary secret store:

- Create an **Azure Resource Manager** service connection and then link a variable group to Key Vault secrets. The Key Vault linkage flow is documented step-by-step (toggle “Link secrets from an Azure key vault as variables”, authorise service connection and vault). citeturn11search2turn10search6  
- Alternatively/in addition, pull secrets at runtime using `AzureKeyVault@2`. citeturn0search2

### Azure DevOps CLI for service connections (what works reliably)

Install + configure the Azure DevOps CLI extension:
- `az extension add --name azure-devops` is the standard installation pattern. citeturn13search0turn13search4  
- You can authenticate using a PAT (`az devops login`) and set defaults for org/project. citeturn13search2turn13search1  

Create endpoints via config JSON:
- `az devops service-endpoint create --service-endpoint-configuration ./file.json` is the supported pattern. citeturn14view0turn17search0

Important caveat: programmatic creation of certain service endpoints (notably Kubernetes service connections) has historically had edge cases where UI-created endpoints work but API-created ones fail, so treat automation here as **“test-first”**. citeturn17search3turn10search3

## Secrets management, governance, and security controls

### Secure storage primitives in Azure DevOps

Use:
- **Secure Files** for file-shaped secrets (e.g., `clouds.yaml`, `cloud.conf`, kubeconfig). Secure files are created in **Pipelines → Library → Secure files**. citeturn1search0turn1search6  
- **DownloadSecureFile@1** to consume secure files in pipelines; note how the task exposes `$(<name>.secureFilePath)`. citeturn22search1turn22search13  
- **Variable groups** for shared variables (including secrets) across pipelines. citeturn0search20turn11search17  
- **Key Vault linked variable groups** to avoid duplicating secrets and centralise rotation. citeturn11search2turn11search14  

### OpenStack credential best practice: application credentials + clouds.yaml

The OpenStack Terraform provider supports:
- `cloud` (entry in `clouds.yaml`) and will fall back to `OS_CLOUD` if omitted.
- `auth_url` and OS_* environment variables.
- `token` authentication (expiring).
- application credential ID + secret. citeturn7view0

Store `clouds.yaml` as a secure file; store the sensitive secret material in Key Vault/secret variables; at runtime, compose a temporary `clouds.yaml` and set:
- `OS_CLIENT_CONFIG_FILE` pointing to that file (openstacksdk searches this path first, then current dir, then `~/.config/openstack`, then `/etc/openstack`). citeturn4search12turn7view0

Application credentials are designed to let applications authenticate without using the user’s password and can be rotated by creating a new credential, updating configuration, then deleting the old one. citeturn5search6turn5search3

### CI/CD gating and change control

For enterprise controls:
- Use **branch policies** and build validation on protected branches (e.g., `main`). citeturn11search0turn11search4  
- Use **Environments approvals and checks** for deployment gating (especially `acc`). citeturn11search1turn11search5  
- Use `ManualValidation@1` to pause and require manual approval within YAML. citeturn9search5turn9search2  
- Restrict service connections to specific pipelines/branches; this is a recognised security control for Azure Pipelines. citeturn29search10turn29search4  

## Agent strategy and firewall rules

### Requested comparison: agent options

| Agent type | Can reach `10.0.0.xx`? | Pros | Cons | Recommendation |
|---|---:|---|---|---|
| Microsoft-hosted agent | Typically **no** | simplest; great for builds/tests | can’t reach private tenant network; not suitable for deploy | Use for CI stages only citeturn23search10 |
| Self-hosted on host VPS | Yes | easiest path to private network | shared blast radius with OpenStack host; must harden | Acceptable (interim) citeturn23search2 |
| Self-hosted on CI utility VM inside tenant | Yes | best isolation; no inbound internet needed | needs VM lifecycle/hardening | **Recommended** citeturn23search2 |
| Dedicated build VM + VPN/peering | Yes (if engineered) | strong separation; scales | more ops | Phase 2+ |

### Self-hosted agent setup (recommended)

Self-hosted agents give you control over installed tooling and preserve caches/config between runs. citeturn23search2  
Microsoft provides a dedicated Linux agent setup procedure (agent pool permissions, registration). citeturn23search0

Network allowlisting: if you enforce outbound restrictions, ensure Azure DevOps endpoints and agent download URLs are allowed; Microsoft specifically notes allowlisting `*.dev.azure.com` or `download.agent.dev.azure.com` for agent downloads. citeturn23search1turn1search2

### Firewall and port rules

Use Kubernetes port/NodePort guidance as baseline:

- Control plane API default: TCP inbound `6443` (cluster-internal only). citeturn28view0  
- NodePort default range: TCP/UDP inbound `30000–32767` (restrict this to reverse-proxy host only). citeturn28view0  

Practical policy for your single-IP setup:
- Host VPS (public): allow inbound **80/443**; allow **22** only from admin IPs; deny other inbound.
- Kubernetes nodes (private): allow **6443** only from CI agent/private admin network; allow NodePorts only from reverse-proxy host; deny public inbound.

## Reference implementation with step-by-step assets

This section is formatted to be copy/paste-ready (and aligns with the attached `.md`/`.docx`).

### Planning checklist

Confirm/define:
- OpenStack cloud name in `clouds.yaml` (e.g., `blueharvestai`)
- Whether OpenStack APIs are reachable from the CI utility VM (recommended)
- Private IPs for control plane and workers (or output them from Terraform)
- DNS records (`site-dev.*`, `site-test.*`, `site-acc.*`) already point to `89.233.107.185`
- Reverse proxy on host can route to ingress NodePorts

### Terraform skeleton for OpenStack provisioning (no public floating IPs)

OpenStack provider authentication reference (clouds.yaml, OS_* env, token, application creds) is documented in the provider’s upstream docs. citeturn7view0  

**File: `infra/providers.tf`**
```hcl
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.53"
    }
  }
}

provider "openstack" {
  cloud = var.os_cloud_name
}
```

**File: `infra/variables.tf`**
```hcl
variable "os_cloud_name"       { type = string }  # matches clouds.yaml entry
variable "k8s_image_id"        { type = string }
variable "k8s_flavor_id"       { type = string }
variable "k8s_keypair"         { type = string }
variable "tenant_network_id"   { type = string }

# optional: create a CI utility VM in the same network
variable "create_ci_vm"        { type = bool default = true }
```

**File: `infra/main.tf`**
```hcl
resource "openstack_compute_instance_v2" "k8s_cp" {
  name      = "k8s-cp-1"
  image_id  = var.k8s_image_id
  flavor_id = var.k8s_flavor_id
  key_pair  = var.k8s_keypair

  network { uuid = var.tenant_network_id }

  user_data = file("${path.module}/cloud-init/k8s-base.yaml")
}

resource "openstack_compute_instance_v2" "k8s_w1" {
  name      = "k8s-w-1"
  image_id  = var.k8s_image_id
  flavor_id = var.k8s_flavor_id
  key_pair  = var.k8s_keypair

  network { uuid = var.tenant_network_id }

  user_data = file("${path.module}/cloud-init/k8s-base.yaml")
}

resource "openstack_compute_instance_v2" "ci_vm" {
  count     = var.create_ci_vm ? 1 : 0
  name      = "ci-utility-1"
  image_id  = var.k8s_image_id
  flavor_id = var.k8s_flavor_id
  key_pair  = var.k8s_keypair

  network { uuid = var.tenant_network_id }

  user_data = file("${path.module}/cloud-init/ci-agent.yaml")
}
```

**File: `infra/outputs.tf`**
```hcl
output "k8s_cp_ip"   { value = openstack_compute_instance_v2.k8s_cp.access_ip_v4 }
output "k8s_w1_ip"   { value = openstack_compute_instance_v2.k8s_w1.access_ip_v4 }
output "ci_vm_ip"    { value = try(openstack_compute_instance_v2.ci_vm[0].access_ip_v4, null) }
```

Cloud config paths: openstacksdk will locate `clouds.yaml` via `OS_CLIENT_CONFIG_FILE`, current dir, `~/.config/openstack`, then `/etc/openstack`. citeturn4search12  

### Kubernetes bootstrap (kubeadm) approach for pipeline orchestration

kubeadm is the standard bootstrap tool; `kubeadm init` creates a control plane, `kubeadm join` joins nodes, and `kubeadm reset` cleans up nodes for rollback. citeturn30search0turn30search1turn30search2turn30search4  

**Bootstrap pattern**
- Cloud-init installs prerequisites (container runtime, kubeadm, kubelet, kubectl).
- Pipeline runs:
  - `kubeadm init` on the control plane.
  - installs CNI (not covered in depth here).
  - uses a join token to add workers.

### OpenStack Cinder CSI for durable WordPress + PostgreSQL storage

Cinder CSI driver overview:
- It’s CSI-compliant and manages lifecycle of Cinder volumes. citeturn8view0turn4search2  
- It expects a `cloud.conf` configuration passed via a Kubernetes Secret in `kube-system` and can be deployed via manifests or Helm chart. citeturn8view0  
- The driver’s StorageClass provisioner is `cinder.csi.openstack.org` and supports parameters such as availability zone and volume type. citeturn8view0  

**Practical pipeline step**: install CSI once (bootstrap pipeline), then use a StorageClass like `cinder-sc` and reference it from PVCs.

### Sample Kubernetes manifests for one namespace (repeat dev/test/acc)

This shows the pattern for **one** namespace; replicate with hostnames and namespace name changed.

**File: `k8s/apps/dev/all.yaml`**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: dev
---
apiVersion: v1
kind: Secret
metadata:
  name: wp-db
  namespace: dev
type: Opaque
stringData:
  POSTGRES_DB: wordpress
  POSTGRES_USER: wp
  POSTGRES_PASSWORD: change-me
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pg-data
  namespace: dev
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: cinder-sc
  resources:
    requests:
      storage: 10Gi
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: dev
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels: { app: postgres }
  template:
    metadata:
      labels: { app: postgres }
    spec:
      containers:
        - name: postgres
          image: postgres:16
          envFrom:
            - secretRef: { name: wp-db }
          ports:
            - containerPort: 5432
          resources:
            requests: { cpu: "100m", memory: "256Mi" }
            limits:   { cpu: "500m", memory: "512Mi" }
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql/data
          livenessProbe:
            exec: { command: ["sh","-c","pg_isready -U $POSTGRES_USER"] }
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            exec: { command: ["sh","-c","pg_isready -U $POSTGRES_USER"] }
            initialDelaySeconds: 10
            periodSeconds: 5
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: pg-data
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: dev
spec:
  selector: { app: postgres }
  ports:
    - name: pg
      port: 5432
      targetPort: 5432
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: wp-uploads
  namespace: dev
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: cinder-sc
  resources:
    requests:
      storage: 10Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wordpress
  namespace: dev
spec:
  replicas: 1
  selector:
    matchLabels: { app: wordpress }
  template:
    metadata:
      labels: { app: wordpress }
    spec:
      containers:
        - name: wordpress
          image: wordpress:6-apache
          env:
            - name: WORDPRESS_DB_HOST
              value: postgres.dev.svc.cluster.local:5432
            - name: WORDPRESS_DB_NAME
              valueFrom: { secretKeyRef: { name: wp-db, key: POSTGRES_DB } }
            - name: WORDPRESS_DB_USER
              valueFrom: { secretKeyRef: { name: wp-db, key: POSTGRES_USER } }
            - name: WORDPRESS_DB_PASSWORD
              valueFrom: { secretKeyRef: { name: wp-db, key: POSTGRES_PASSWORD } }
          ports:
            - containerPort: 80
          resources:
            requests: { cpu: "100m", memory: "256Mi" }
            limits:   { cpu: "500m", memory: "512Mi" }
          volumeMounts:
            - name: uploads
              mountPath: /var/www/html/wp-content/uploads
          readinessProbe:
            httpGet: { path: "/", port: 80 }
            initialDelaySeconds: 10
            periodSeconds: 5
          livenessProbe:
            httpGet: { path: "/", port: 80 }
            initialDelaySeconds: 30
            periodSeconds: 10
      volumes:
        - name: uploads
          persistentVolumeClaim:
            claimName: wp-uploads
---
apiVersion: v1
kind: Service
metadata:
  name: wordpress
  namespace: dev
spec:
  selector: { app: wordpress }
  ports:
    - name: http
      port: 80
      targetPort: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: wordpress
  namespace: dev
spec:
  ingressClassName: nginx
  rules:
    - host: site-dev.blueharvestai.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: wordpress
                port:
                  number: 80
```

### Azure DevOps YAML pipeline templates

Azure Pipelines Kubernetes deployment tasks:
- `Kubernetes@1` supports connection types “Kubernetes Service Connection” or “None”. citeturn24search2  
- `HelmDeploy@1` supports Kubernetes service connections for any Kubernetes cluster. citeturn24search8turn24search1  
- `KubernetesManifest@1` exists for deploying/baking manifests. citeturn24search0  
- Overview: Azure Pipelines supports deploying to non-AKS Kubernetes too. citeturn24search9  

**Pipeline 1: Terraform provisioning (no floating IPs)**  
Key ideas:
- download `clouds.yaml` secure file
- set `OS_CLIENT_CONFIG_FILE` and `OS_CLOUD`
- run `terraform init/plan/apply`
- gate apply with manual approval

Secure files usage and downloading in pipelines is documented. citeturn1search0turn22search1turn22search13  

**Pipeline 2: Bootstrap Kubernetes (kubeadm over SSH)**  
Use `SSH@0` to run shell commands and scripts on remote machines. citeturn9search0  

**Pipeline 3: Deploy apps to dev/test/acc**  
Use `Kubernetes@1` with the namespace-scoped service connections (`k8s-dev`, `k8s-test`, `k8s-acc`). citeturn24search2  

**Pipeline 4: GitOps with Argo CD + Git repo**
- Argo CD automated sync means pipelines can deploy by committing to Git (no direct access to Argo CD API required). citeturn26view0  
- Enable self-heal with Argo CD’s sync policy. citeturn26view0  
- Configure Git webhooks to Argo CD’s `/api/webhook` endpoint to reduce polling latency. citeturn12search0turn12search16  
- Add private repo credentials in Argo CD via UI/CLI. citeturn12search1  

### Validation and troubleshooting

Validation commands (run from the self-hosted agent network):

```bash
kubectl get nodes
kubectl get pods -A
kubectl -n kube-system get pods | grep cinder
kubectl -n dev get all
kubectl -n dev get pvc
```

Common issues and fixes:

- **Pipeline can’t reach Kubernetes API**: your agent is not in a network that can route to `10.0.0.xx:6443`. Re-run deploy stages on the self-hosted agent inside the tenant network. (This is a reachability constraint, not a YAML problem.) citeturn28view0turn23search2  
- **“Could not find any secrets associated with the Service Account”**: use TokenRequest tokens (`kubectl create token`) or create an explicit service-account-token Secret if required by the toolchain. citeturn27search0turn27search3turn27search2  
- **Agent download/update blocked**: allowlist Azure DevOps URLs and agent download domains. citeturn23search1turn1search2  

### Cleanup plan

- OpenStack: `terraform destroy` to remove VMs/networks; rotate/delete Keystone application credentials after teardown. citeturn5search3turn5search6  
- Azure DevOps: delete service connections and secure files when no longer needed. citeturn1search9turn1search0  
- Kubernetes: delete namespaces as needed and uninstall CSI/ingress/GitOps components.

