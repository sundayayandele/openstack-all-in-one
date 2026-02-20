# Small single-VPS Kubernetes on OpenStack with Terraform for dev, test, acc WordPress + PostgreSQL

## Executive summary

This report designs and documents a pragmatic way to run a small Kubernetes environment on **one OpenStack VPS** (Ubuntu 22.04, 64 GB RAM, one public IP) provisioned via Terraform from a remote PC, hosting three namespaces (**dev**, **test**, **acc**) with one WordPress pod and one PostgreSQL pod per namespace. The design is explicitly constrained by the *single public IP* and the realities of a *single-node cluster*. citeturn26view0turn13search4turn20view0

The recommended solution is:

- **Cluster topology:** a **single-node kubeadm cluster** where the control plane node is also the worker (pods scheduled on the control plane after removing the default taint). This is the only topology that fits one VPS without additional nodes; it is explicitly supported as a single-machine pattern by kubeadm documentation. citeturn26view0turn25view0  
- **Networking (CNI):** **Calico** (operator install), because Kubernetes NetworkPolicies require a supporting network plugin, and Calico is widely used and documented. citeturn15search1turn25view0turn24search29  
- **Ingress exposure on one public IP:** **ingress-nginx** on “bare-metal” style setups, using the **host network** method so ports **80/443** can be bound directly on the node, avoiding NodePort high ports for end-users. This matters when you want three environments accessible cleanly via hostnames on one IP. citeturn32view0  
- **Persistent storage:** **local PersistentVolumes** (static PVs bound to directories on the single node). This avoids the operational weight of a cloud CSI integration for a single-node learning/staging VPS while still using PVCs, StorageClass objects, and clear separation per namespace. You should avoid raw hostPath where possible; Kubernetes explicitly warns hostPath carries security risks and suggests local PVs instead. citeturn18view0  
  - An “advanced” option is OpenStack **Cinder CSI** dynamic provisioning (`cinder.csi.openstack.org`), which provides snapshots and dynamic PVs but adds configuration and lifecycle overhead. It’s documented and feature-rich, but it is not the simplest path for a single VPS. citeturn31view0turn17view0

A critical application-level caveat must be stated upfront: **WordPress officially requires MySQL/MariaDB**, not PostgreSQL. Running WordPress on PostgreSQL is **non-standard** and typically requires a compatibility layer/plugin (e.g., PG4WP) and PHP PostgreSQL extensions; this may be unsuitable for production and increases risk. citeturn4search2turn4search10turn16search2  
This report therefore documents:
1) a **recommended, standards-aligned** deployment (WordPress + MySQL/MariaDB), and  
2) an **“if you insist”** experimental track (WordPress + PostgreSQL via PG4WP-style approach). citeturn4search2turn16search2

## Architecture choices and option comparison

### OpenStack reality with one public IP

In OpenStack deployments, instances commonly have a private IP and may be reachable via a **floating IP** using NAT. With only one public IP available, you cannot rely on per-service public IPs. citeturn13search4turn13search0turn20view0  
Consequences:

- You should expose *multiple apps* via **virtual hosting** (hostnames) behind one ingress point. citeturn32view0  
- LoadBalancer services that require extra IPs are typically not viable in a one-IP environment; bare-metal techniques (NodePort / hostNetwork) apply. citeturn32view0

### Cluster topology options

| Option | What it is | Pros | Cons | Fit for this VPS? | Recommendation |
|---|---|---|---|---|---|
| Single-node kubeadm (control plane + worker) | One node runs etcd + API server + workloads | Lowest cost and simplest within constraints; explicitly supported for kubeadm + single host patterns | No HA; if node fails, cluster and etcd can be lost; kubeadm notes single control-plane is not resilient | Yes | **Recommended** citeturn26view0turn25view0 |
| 1 control-plane + separate worker VMs | Multiple VMs in same OpenStack tenant; only CP has floating IP | Better workload isolation; closer to real multi-node | Requires extra VMs (not “single VPS”); more networking & ops | Not per stated constraint | Not recommended |
| Lightweight distro (e.g., k3s / microk8s) | Single-node Kubernetes distribution | Easier bootstrap; often less resource overhead | Deviates from kubeadm/Kubernetes docs path; different lifecycle tooling | Possible | Optional alternative (not primary) |
| “Nested” workers inside the VPS | Run VMs/containers-as-nodes inside the VPS | Experimentation | Complexity; debugging overhead; poor ROI | Possible but poor | Not recommended |

Kubeadm documentation explicitly describes how to run a **single control-plane** cluster and shows how to remove the control-plane taint if you want a single machine cluster to schedule normal workloads. citeturn26view0turn25view0

### Storage options

| Option | How it works | Pros | Cons | Recommendation |
|---|---|---|---|---|
| hostPath directly in Pods | Pods mount host directories | Very quick | Kubernetes warns of significant security risks and operational pitfalls; no PV/PVC abstraction | Avoid unless you must citeturn18view0 |
| Local PersistentVolumes (static) | PVs use `local:` paths on node; apps use PVCs | Keeps PV/PVC workflow; clear per-namespace data separation; good for one-node | Manual PV creation; data tied to node; no dynamic provisioning | **Recommended baseline** citeturn18view0turn19view0 |
| OpenStack Cinder CSI | StorageClass calls `cinder.csi.openstack.org` | Dynamic provisioning; volume expansion; snapshots; richer lifecycle | Requires cloud config secret, CSI components; more moving parts for single-node | Advanced option citeturn31view0turn17view0 |
| “VM-level” Cinder volumes + local PV | Attach volumes via Terraform; mount them; expose as local PV | OpenStack durability while keeping Kubernetes simple | Device mapping/mount automation complexity; still node-bound in Kubernetes sense | Optional hybrid (only if you’re comfortable) citeturn12view0turn23view1 |

Kubernetes explicitly warns that hostPath is a powerful “escape hatch” with **many security risks** and suggests using a **local PersistentVolume** instead when possible. citeturn18view0  
If you later need “cloud-like” dynamic storage, OpenStack’s Cinder CSI driver is documented as a CSI-compliant driver and exposes features such as dynamic provisioning and snapshots. citeturn31view0

### CNI and NetworkPolicy options

| CNI | Pros | Cons | Notable notes | Recommendation |
|---|---|---|---|---|
| Calico | Strong NetworkPolicy support; widely deployed; documented single-host install | More components than Flannel | Tigera operator-based install documented; includes taint removal step for single-host clusters | **Recommended** citeturn25view0turn15search1 |
| Flannel | Very simple overlay | NetworkPolicy enforcement not provided by Flannel alone | Flannel docs note kubeadm `--pod-network-cidr=10.244.0.0/16` requirement | Acceptable for simple networking-only labs citeturn14view0turn26view0 |
| Weave Net | Historically simple | Upstream repository was archived (read-only) | Repo archived notice indicates project risk for new builds | Not recommended citeturn24search2turn15search1 |

Kubernetes NetworkPolicies require a network plugin that supports enforcement. citeturn15search1  
Additionally, the upstream Weave Net repository was archived in June 2024, which is a material lifecycle signal for choosing it today. citeturn24search2

### Ingress exposure options with one public IP

| Approach | Pros | Cons | Recommendation |
|---|---|---|---|
| NodePort per app | Simple conceptually | Many ports; awkward public URLs; NodePorts are in 30000–32767 by default | Not ideal for human-facing WordPress citeturn32view0 |
| ingress-nginx via NodePort | One controller; route by host/path | External clients must use NodePort unless you add additional routing/NAT | Good “middle ground” if you accept high ports citeturn32view0 |
| ingress-nginx via host network | Clean 80/443 binding on the node; one IP can host multiple sites cleanly | Security considerations (controller sees host network); only one controller pod per node | **Recommended for one-IP VPS** citeturn32view0 |
| MetalLB | Can provide LoadBalancer IPs | Requires an IP pool you cannot share with node IPs | Not viable with only one public IP | Not recommended citeturn32view0 |

The ingress-nginx project documents “bare-metal considerations” and specifically describes NodePort constraints and the hostNetwork method (including DNS policy requirements and security considerations). citeturn32view0

### Cluster topology diagram

```mermaid
flowchart TB
  Internet((Internet))
  DNS[DNS: dev.example.com / test.example.com / acc.example.com<br/>all A-record -> single public IP]
  Internet --> DNS --> FIP[OpenStack Floating/Public IP]

  subgraph OS[OpenStack VPS: Ubuntu 22.04]
    direction TB

    subgraph K8s[Kubernetes single-node (kubeadm)]
      direction TB
      CP[Control plane components<br/>API server, scheduler, controller-manager, etcd]
      CNI[Calico CNI]
      IN[ingress-nginx controller<br/>hostNetwork: true<br/>ports 80/443 on node]
      subgraph NS1[Namespace: dev]
        WP1[WordPress Pod]
        DB1[PostgreSQL Pod]
      end
      subgraph NS2[Namespace: test]
        WP2[WordPress Pod]
        DB2[PostgreSQL Pod]
      end
      subgraph NS3[Namespace: acc]
        WP3[WordPress Pod]
        DB3[PostgreSQL Pod]
      end
    end
  end

  FIP --> IN
  IN --> WP1
  IN --> WP2
  IN --> WP3
  WP1 --> DB1
  WP2 --> DB2
  WP3 --> DB3
```

## Detailed planning and risk management

### Assumptions and prerequisites

- You have OpenStack API access (project/tenant scope) and can provision at least one instance and (optionally) volumes and floating IPs. citeturn10view0turn20view0  
- Terraform runs on a remote PC with:
  - outbound internet access for provider/plugin downloads and for fetching Kubernetes manifests/charts,
  - SSH access to the provisioned VPS. citeturn10view1  
- The VPS is Ubuntu 22.04 published by entity["company","Canonical","ubuntu publisher"]. citeturn27search2  
- Kubernetes versioning: kubeadm install docs note that **pkgs.k8s.io** repos are the modern path and legacy repos were deprecated/frozen; plan to pick a specific minor version repository. citeturn28view2

### Work breakdown structure

**Phase A: Infrastructure provisioning (Terraform from remote PC)**  
Deliverables: instance, security groups, floating IP association, DNS plan.

**Phase B: Node bootstrap (on VPS)**  
Deliverables: container runtime, kubeadm/kubelet, cluster initialised.

**Phase C: Cluster networking and ingress**  
Deliverables: Calico installed; ingress-nginx installed and reachable on 80/443.

**Phase D: Storage and namespaces**  
Deliverables: StorageClass, PVs, PVCs; namespaces dev/test/acc; baseline NetworkPolicies.

**Phase E: Workloads**  
Deliverables: Postgres + WordPress per namespace; readiness/liveness probes; resource sizing; secrets/config.

**Phase F: Operations**  
Deliverables: backups (CronJob + pg_dump), basic monitoring (metrics-server), logging approach, security stance, rollback plan.

### Key risks and mitigations

- **Single-node resilience:** kubeadm explicitly notes a single control-plane node means loss of control plane can mean data loss; mitigate with backups (etcd + application data) and scripted rebuild. citeturn26view0turn27search3  
- **WordPress + PostgreSQL compatibility risk:** WordPress officially expects MySQL/MariaDB; PostgreSQL requires non-standard plugins/approaches. Mitigate by using MySQL/MariaDB in production-like setups, and treat PostgreSQL use as experimental. citeturn4search2turn16search2  
- **State leakage in Terraform:** OpenStack provider docs warn some values (e.g., instance admin password) are stored in state; compute keypair resource warns private keys may be stored unencrypted in state. Mitigate by not generating private keys in Terraform and using a secure state backend and access controls. citeturn10view1turn23view0  
- **Ingress exposure security:** ingress-nginx hostNetwork mode explicitly raises security considerations; mitigate by minimising exposed ports, limiting admin access, applying NetworkPolicies, and hardening the host firewall/security group. citeturn32view0turn12view2turn27search2  
- **Swap and node misconfiguration:** kubeadm docs state kubelet fails to start by default if swap is detected; mitigate by disabling swap or explicitly configuring swap tolerance. citeturn28view2turn27search5

## Terraform codebase and infrastructure provisioning

### Terraform structure

HashiCorp recommends a standard module structure and a conventional `./modules/<name>` layout for reusable child modules. citeturn5search1turn5search13  
Suggested repository layout:

```text
repo/
  infra/
    versions.tf
    providers.tf
    main.tf
    variables.tf
    outputs.tf
    cloud-init/
      user-data.yaml
    modules/
      openstack_vps/
        main.tf
        variables.tf
        outputs.tf
  platform/
    versions.tf
    providers.tf
    ingress-nginx.tf
    calico.tf
    storage-local.tf
  apps/
    manifests/
      00-namespaces.yaml
      10-storage.yaml
      20-dev.yaml
      21-test.yaml
      22-acc.yaml
      30-networkpolicies.yaml
      40-ingress.yaml
      90-backups.yaml
```

Rationale: separate Terraform states reduce coupling between “infrastructure creation” and “Kubernetes API provisioning”, because kubeconfig availability happens *after* the cluster is initialised (a sequencing reality, not just a style choice).

### OpenStack provider configuration patterns

The OpenStack Terraform provider supports:
- Explicit `auth_url`, `user_name`, `password`, etc., and/or
- `cloud = "<name>"` referencing a `clouds.yaml` entry, defaulting to `OS_CLOUD` if omitted. citeturn10view0turn5search0  

OpenStack `clouds.yaml` discovery locations and `OS_CLIENT_CONFIG_FILE` override are documented via os-client-config conventions. citeturn5search0  

### Example Terraform (infra) snippets

**versions.tf**

```hcl
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.53.0"
    }
  }
}
```

The provider’s own documentation shows this source and version pattern and explains credential configuration via arguments and environment variables. citeturn10view0  

**providers.tf**

```hcl
provider "openstack" {
  cloud  = var.os_cloud
  region = var.os_region
}
```

`cloud` maps to `clouds.yaml` and can be sourced from `OS_CLOUD` if not set in configuration. citeturn10view0turn5search0  

**Key pair**

Do **not** generate OpenStack keypairs with private keys inside Terraform state for production-like usage; the resource includes an explicit security notice that the private key can be stored unencrypted in the state file. Use an externally generated SSH key and upload only the public key. citeturn23view0  

```hcl
resource "openstack_compute_keypair_v2" "this" {
  name       = var.keypair_name
  public_key = file(var.ssh_public_key_path)
}
```

**Security group + rules**

Neutron security groups and separate rules are documented as distinct resources. citeturn12view1turn12view2  

```hcl
resource "openstack_networking_secgroup_v2" "k8s" {
  name        = "k8s-single-node"
  description = "Kubernetes single-node: ssh + http/https"
  delete_default_rules = true
}

resource "openstack_networking_secgroup_rule_v2" "ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = var.admin_cidr
  security_group_id = openstack_networking_secgroup_v2.k8s.id
}

resource "openstack_networking_secgroup_rule_v2" "http" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.k8s.id
}

resource "openstack_networking_secgroup_rule_v2" "https" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.k8s.id
}

# Egress allow-all (tighten later once you know requirements)
resource "openstack_networking_secgroup_rule_v2" "egress_all" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = ""
  security_group_id = openstack_networking_secgroup_v2.k8s.id
}
```

**Instance (with cloud-init user_data)**

The compute instance resource supports `user_data` and notes it can come from inline content or template_cloudinit_config. It also warns that “all arguments including the instance admin password” are stored in state as plain-text. citeturn10view1  

```hcl
resource "openstack_compute_instance_v2" "k8s" {
  name            = var.instance_name
  image_name      = var.image_name
  flavor_name     = var.flavor_name
  key_pair        = openstack_compute_keypair_v2.this.name
  security_groups = [openstack_networking_secgroup_v2.k8s.name]

  network {
    name = var.private_network_name
  }

  user_data = file("${path.module}/cloud-init/user-data.yaml")
}
```

**Floating IP allocation + association**

A floating IP can be allocated from a named pool. citeturn20view0  
Association to an instance port can be done via `openstack_networking_floatingip_associate_v2`. citeturn11view0  

A common pattern is:
1) allocate floating IP,  
2) look up the instance port,  
3) associate.

```hcl
resource "openstack_networking_floatingip_v2" "fip" {
  pool = var.floating_ip_pool
}

data "openstack_networking_port_v2" "instance_port" {
  device_id = openstack_compute_instance_v2.k8s.id
  network_id = data.openstack_networking_network_v2.private.id
}

resource "openstack_networking_floatingip_associate_v2" "assoc" {
  floating_ip = openstack_networking_floatingip_v2.fip.address
  port_id     = data.openstack_networking_port_v2.instance_port.id
}
```

The provider documents the port data source and floating IP resources shown above. citeturn22view2turn20view0turn11view0

## Step-by-step build guide

This section is formatted as a runbook you can paste into a Word document.

### Remote PC preparation

1) Install tooling:
- Terraform (matching your policy/versioning).
- `kubectl` (compatible with your cluster version).
- Optional: OpenStack CLI, Helm.

2) Prepare OpenStack credentials:
- Obtain a `clouds.yaml` from your OpenStack environment (Horizon often offers it) and place it in a standard location such as `~/.config/openstack/clouds.yaml`. os-client-config documents default search locations and the `OS_CLIENT_CONFIG_FILE` override. citeturn5search0turn10view0  

Example:

```bash
mkdir -p ~/.config/openstack
cp ./clouds.yaml ~/.config/openstack/clouds.yaml
export OS_CLOUD="mycloud"
```

3) Create an SSH keypair locally (recommended) and keep the private key off Terraform state. citeturn23view0  

```bash
ssh-keygen -t ed25519 -f ~/.ssh/k8s_openstack_vps -C "k8s-vps"
```

4) Initialise and apply Terraform (infra):

```bash
cd repo/infra
terraform init
terraform plan -out tfplan
terraform apply tfplan
```

5) Capture outputs (public IP / SSH connection target):

```bash
terraform output
# Expect something like: public_ip, ssh_user, instance_id
```

---

### VPS bootstrap (SSH into the node)

SSH in:

```bash
ssh -i ~/.ssh/k8s_openstack_vps ubuntu@<PUBLIC_IP>
```

#### Host firewall sanity (optional but strongly advised)

If you use UFW on Ubuntu, Canonical’s Ubuntu Server docs show how to allow access from specific hosts/subnets and ports. citeturn27search2  

Example (restrict SSH to your admin IP/CIDR; allow HTTP/HTTPS from anywhere):

```bash
sudo ufw allow proto tcp from <YOUR_ADMIN_CIDR> to any port 22
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

Also ensure your OpenStack security group matches the intention; Neutron SG rules are your first line of exposure control. citeturn12view2turn15search0  

#### Disable swap (kubelet default behaviour)

Kubeadm install docs state: “The default behaviour of a kubelet is to fail to start if swap memory is detected on a node,” so swap should be disabled unless you explicitly configure swap tolerance. citeturn28view2turn27search5  

```bash
sudo swapoff -a
sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
```

#### Install container runtime and align cgroup driver

Kubernetes docs recommend that if kubelet uses `systemd` cgroup driver (kubeadm defaults to `systemd` if not set), your container runtime should also use `systemd`. citeturn13search13turn13search1  

Install containerd (example approach; adjust to your policy) and configure:

- containerd to use `SystemdCgroup = true`
- kubelet cgroup driver to match

The Kubernetes cgroup driver guidance explains the need for matching cgroup drivers. citeturn13search1turn13search13  

#### Install kubeadm / kubelet / kubectl using pkgs.k8s.io

The kubeadm install page notes that legacy repositories were deprecated/frozen and that `pkgs.k8s.io` is the recommended path for versions released after September 2023. citeturn28view2  

Follow the official per-minor-version repository steps from the kubeadm install page for your chosen Kubernetes minor version. citeturn28view2  

#### Initialise the cluster (single host)

Calico’s single-host install guide uses:

```bash
sudo kubeadm init --pod-network-cidr=192.168.0.0/16
```

and cautions to pick a different CIDR if that range overlaps your environment. citeturn25view0  

After init, set up kubectl for your non-root user (also shown in kubeadm output patterns). citeturn26view0turn25view0  

```bash
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown "$(id -u):$(id -g)" $HOME/.kube/config
```

#### Install Calico (operator method)

Calico’s single-host guide installs the Tigera operator and CRDs, then creates Calico custom resources. citeturn25view0  

```bash
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.31.3/manifests/operator-crds.yaml
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.31.3/manifests/tigera-operator.yaml
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.31.3/manifests/custom-resources-bpf.yaml
```

Wait for Calico pods:

```bash
watch kubectl get pods -n calico-system
```

#### Allow workloads on the control plane (single-node cluster)

Both kubeadm and Calico single-node documentation show removing the default control-plane taint so pods can schedule on this node. citeturn26view0turn25view0  

```bash
kubectl taint nodes --all node-role.kubernetes.io/control-plane-
```

---

### Install ingress-nginx for one public IP

#### Recommended: hostNetwork approach

The ingress-nginx bare-metal guide documents that NodePort exposes unprivileged ports (default 30000–32767) and that changing NodePort range to include 80/443 is discouraged. It also documents the hostNetwork approach to bind 80/443 directly, along with DNS policy requirements and security considerations. citeturn32view0  

Install ingress-nginx (bare-metal manifest), then patch the controller to use host networking:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/baremetal/deploy.yaml

kubectl -n ingress-nginx patch deployment ingress-nginx-controller \
  --type merge \
  -p '{"spec":{"template":{"spec":{"hostNetwork":true,"dnsPolicy":"ClusterFirstWithHostNet"}}}}'
```

Validate:

```bash
kubectl -n ingress-nginx get pods -o wide
sudo ss -lntp | egrep ':80|:443' || true
```

Notes you should capture in your Word doc:
- hostNetwork mode has explicit security implications (controller shares host network namespace). citeturn32view0  
- only one ingress-nginx controller pod per node is feasible due to port binding constraints. citeturn32view0  

---

### Prepare local persistent storage directories on the node

Create per-namespace directories on the node (example):

```bash
sudo mkdir -p /var/lib/k8s-volumes/{dev,test,acc}/{postgres,wordpress}
sudo chown -R root:root /var/lib/k8s-volumes
sudo chmod -R 700 /var/lib/k8s-volumes
```

This report uses local PVs to avoid hostPath in Pods (Kubernetes warns hostPath has many security risks). citeturn18view0  

---

### Get kubeconfig to the remote PC (securely)

Kubeadm create-cluster docs show copying `/etc/kubernetes/admin.conf` to another machine using scp, but also warn that `admin.conf` grants cluster-admin privileges and should not be shared broadly. citeturn26view0  

Preferred approach for a single admin operator: copy it to your workstation and restrict filesystem permissions, or use SSH tunnelling so the API server is not broadly exposed on the internet.

Example copy (admin-only use):

```bash
# on remote PC
scp -i ~/.ssh/k8s_openstack_vps ubuntu@<PUBLIC_IP>:/etc/kubernetes/admin.conf ./kubeconfig-admin.conf
chmod 600 ./kubeconfig-admin.conf
export KUBECONFIG=$PWD/kubeconfig-admin.conf
kubectl get nodes
```

## Kubernetes manifests for dev, test, acc

### Important compatibility note: WordPress + PostgreSQL

- WordPress’ official requirements specify MySQL/MariaDB (not PostgreSQL). citeturn4search2  
- WordPress documentation acknowledges alternative database work exists but this is not the standard path and is ecosystem-dependent. citeturn4search10  
- PG4WP-style projects exist to run WordPress on PostgreSQL, but treat this as experimental unless you have strong reasons and testing. citeturn16search2  

Accordingly, below are:
- **Track A (recommended):** WordPress + MySQL/MariaDB (standards-aligned).  
- **Track B (experimental):** WordPress + PostgreSQL.

You asked for PostgreSQL, so the sample manifests include PostgreSQL; Track A is provided to keep the overall report technically rigorous.

### Shared objects: Namespaces

`00-namespaces.yaml`

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: dev
---
apiVersion: v1
kind: Namespace
metadata:
  name: test
---
apiVersion: v1
kind: Namespace
metadata:
  name: acc
```

### Shared objects: StorageClass and local PVs

`10-storage.yaml` (replace `REPLACE_WITH_NODE_NAME`)

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-static
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: Immediate
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-dev-postgres
spec:
  capacity:
    storage: 5Gi
  accessModes: ["ReadWriteOnce"]
  storageClassName: local-static
  persistentVolumeReclaimPolicy: Retain
  local:
    path: /var/lib/k8s-volumes/dev/postgres
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
          - key: kubernetes.io/hostname
            operator: In
            values:
              - REPLACE_WITH_NODE_NAME
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-dev-wordpress
spec:
  capacity:
    storage: 2Gi
  accessModes: ["ReadWriteOnce"]
  storageClassName: local-static
  persistentVolumeReclaimPolicy: Retain
  local:
    path: /var/lib/k8s-volumes/dev/wordpress
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
          - key: kubernetes.io/hostname
            operator: In
            values:
              - REPLACE_WITH_NODE_NAME
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-test-postgres
spec:
  capacity:
    storage: 5Gi
  accessModes: ["ReadWriteOnce"]
  storageClassName: local-static
  persistentVolumeReclaimPolicy: Retain
  local:
    path: /var/lib/k8s-volumes/test/postgres
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
          - key: kubernetes.io/hostname
            operator: In
            values:
              - REPLACE_WITH_NODE_NAME
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-test-wordpress
spec:
  capacity:
    storage: 2Gi
  accessModes: ["ReadWriteOnce"]
  storageClassName: local-static
  persistentVolumeReclaimPolicy: Retain
  local:
    path: /var/lib/k8s-volumes/test/wordpress
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
          - key: kubernetes.io/hostname
            operator: In
            values:
              - REPLACE_WITH_NODE_NAME
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-acc-postgres
spec:
  capacity:
    storage: 5Gi
  accessModes: ["ReadWriteOnce"]
  storageClassName: local-static
  persistentVolumeReclaimPolicy: Retain
  local:
    path: /var/lib/k8s-volumes/acc/postgres
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
          - key: kubernetes.io/hostname
            operator: In
            values:
              - REPLACE_WITH_NODE_NAME
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-acc-wordpress
spec:
  capacity:
    storage: 2Gi
  accessModes: ["ReadWriteOnce"]
  storageClassName: local-static
  persistentVolumeReclaimPolicy: Retain
  local:
    path: /var/lib/k8s-volumes/acc/wordpress
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
          - key: kubernetes.io/hostname
            operator: In
            values:
              - REPLACE_WITH_NODE_NAME
```

### Per-namespace: PostgreSQL + WordPress (Track B: experimental)

The PostgreSQL official image documents required environment variables such as `POSTGRES_PASSWORD` and its role in initialisation. citeturn16search1  
For “small” containers, set resource requests/limits; Kubernetes docs explain requests/limits semantics and provide CPU/memory examples. citeturn5search2turn5search10turn5search22  
Use liveness/readiness probes as per Kubernetes probe documentation. citeturn5search3turn5search7  

`20-dev.yaml` (repeat for test/acc with name changes)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pg-secret
  namespace: dev
type: Opaque
stringData:
  POSTGRES_DB: wpdb
  POSTGRES_USER: wpuser
  POSTGRES_PASSWORD: "REPLACE_ME_STRONG_PASSWORD"
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pg-data
  namespace: dev
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: local-static
  resources:
    requests:
      storage: 5Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: dev
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
        - name: postgres
          image: postgres:16
          ports:
            - containerPort: 5432
          envFrom:
            - secretRef:
                name: pg-secret
          env:
            - name: PGDATA
              value: /var/lib/postgresql/data/pgdata
          volumeMounts:
            - name: pg-data
              mountPath: /var/lib/postgresql/data
          resources:
            requests:
              cpu: "100m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "1Gi"
          readinessProbe:
            exec:
              command: ["sh", "-c", "pg_isready -U $POSTGRES_USER -d $POSTGRES_DB"]
            initialDelaySeconds: 10
            periodSeconds: 10
          livenessProbe:
            exec:
              command: ["sh", "-c", "pg_isready -U $POSTGRES_USER -d $POSTGRES_DB"]
            initialDelaySeconds: 30
            periodSeconds: 20
      volumes:
        - name: pg-data
          persistentVolumeClaim:
            claimName: pg-data
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: dev
spec:
  selector:
    app: postgres
  ports:
    - name: pg
      port: 5432
      targetPort: 5432
  type: ClusterIP
---
apiVersion: v1
kind: Secret
metadata:
  name: wp-secret
  namespace: dev
type: Opaque
stringData:
  WP_DB_HOST: "postgres.dev.svc.cluster.local"
  WP_DB_NAME: "wpdb"
  WP_DB_USER: "wpuser"
  WP_DB_PASSWORD: "REPLACE_ME_STRONG_PASSWORD"
  WP_ADMIN_USER: "admin"
  WP_ADMIN_PASSWORD: "REPLACE_ME_ADMIN_PASSWORD"
  WP_ADMIN_EMAIL: "admin@example.com"
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: wp-data
  namespace: dev
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: local-static
  resources:
    requests:
      storage: 2Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wordpress
  namespace: dev
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wordpress
  template:
    metadata:
      labels:
        app: wordpress
    spec:
      containers:
        - name: wordpress
          # IMPORTANT: this must be a custom image that includes PHP pgsql extensions + PG4WP drop-in,
          # or you must add an initContainer to install those components.
          image: ghcr.io/YOUR_ORG/wordpress-pg:latest
          ports:
            - containerPort: 80
          envFrom:
            - secretRef:
                name: wp-secret
          volumeMounts:
            - name: wp-data
              mountPath: /var/www/html
          resources:
            requests:
              cpu: "100m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "768Mi"
          readinessProbe:
            httpGet:
              path: /wp-login.php
              port: 80
            initialDelaySeconds: 20
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /wp-login.php
              port: 80
            initialDelaySeconds: 60
            periodSeconds: 20
      volumes:
        - name: wp-data
          persistentVolumeClaim:
            claimName: wp-data
---
apiVersion: v1
kind: Service
metadata:
  name: wordpress
  namespace: dev
spec:
  selector:
    app: wordpress
  ports:
    - name: http
      port: 80
      targetPort: 80
  type: ClusterIP
```

### Ingress objects for dev/test/acc

`40-ingress.yaml` (replace hostnames)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: dev-wordpress
  namespace: dev
spec:
  ingressClassName: nginx
  rules:
    - host: dev.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: wordpress
                port:
                  number: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-wordpress
  namespace: test
spec:
  ingressClassName: nginx
  rules:
    - host: test.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: wordpress
                port:
                  number: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: acc-wordpress
  namespace: acc
spec:
  ingressClassName: nginx
  rules:
    - host: acc.example.com
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

Ingress routing by host is the natural mechanism to run multiple sites on one public IP. The ingress-nginx bare-metal documentation focuses on exactly these exposure problems in environments without cloud load balancers. citeturn32view0  

### Baseline NetworkPolicies (optional but strongly recommended with Calico)

NetworkPolicies allow you to control traffic at L3/L4, and Kubernetes notes your cluster must use a plugin that enforces them. citeturn15search1turn25view0  

A minimal pattern per namespace:

- Default deny ingress and egress.
- Allow DNS to kube-system.
- Allow ingress to WordPress from ingress-nginx.
- Allow WordPress → Postgres.

(Exact label selectors for ingress-nginx and CoreDNS may differ depending on your deployment; treat this as a template to tune.)

## Validation, operations, security, and cleanup

### Validation checklist

1) Node and system pods:

```bash
kubectl get nodes -o wide
kubectl get pods -A
```

CoreDNS typically won’t become Ready until a CNI is installed (kubeadm explicitly notes networking add-on is required). citeturn26view0turn24search29  

2) Ports and reachability

Kubernetes documents required ports/protocols for control-plane components; use this to validate firewall/security group alignment. citeturn15search0turn28view2  

3) Ingress check

```bash
kubectl -n ingress-nginx get pods -o wide
kubectl get ingress -A
curl -I http://dev.example.com
```

4) Workload readiness

```bash
kubectl -n dev get pods,svc,pvc
kubectl -n dev describe pod postgres
kubectl -n dev logs deploy/postgres
kubectl -n dev logs deploy/wordpress
```

### Backups

#### PostgreSQL logical backups (recommended)

`pg_dump` is the standard utility for exporting a PostgreSQL database; the official docs state it makes consistent exports and does not block concurrent access in typical cases. citeturn16search3turn16search39  
Schedule a Kubernetes CronJob; CronJob is explicitly meant for periodic tasks such as backups. citeturn15search3  

Example (per namespace) outline:
- CronJob runs `pg_dump` using a Postgres client image.
- Output is written to a backup PVC (or off-cluster object storage if you add it later).

### Basic monitoring and logging

- **Metrics:** Metrics Server installation is documented; it can be installed from a YAML manifest or Helm chart, and it enables Metrics API consumption such as `kubectl top`. citeturn33search2turn33search10  
- **Logging:** Kubernetes logging architecture docs state that cluster-level logging typically requires storage and lifecycle independent of nodes/pods, and that Kubernetes does not provide a native storage solution for logs (you integrate with external backends). citeturn33search0  
For a small VPS, a sensible baseline is:
- use `kubectl logs` for application troubleshooting,
- keep system component logs on the node (systemd journal) and document retention,
- add a lightweight log forwarder later if required.

### Secrets and configuration hygiene

Kubernetes defines Secrets as objects for small sensitive data and provides good-practice guidance; do not hardcode credentials in manifests committed to git. citeturn15search2turn15search18  
Also note kubeadm warns that the generated admin kubeconfig should not be shared. citeturn26view0  

### Security posture checklist

- **Network exposure minimised**: Only 22 (restricted), 80, 443 public; avoid exposing 6443 unless restricted to your IP or tunnelled. Ports and Protocols reference is your baseline for cluster internals. citeturn15search0turn27search2  
- **OpenStack SG + host firewall aligned**: Neutron security group rules are explicit resources with protocol/port ranges; use them as a declarative perimeter. citeturn12view2  
- **RBAC**: use namespace-scoped Roles for developers; keep cluster-admin credentials limited. citeturn26view0turn15search2  
- **NetworkPolicies**: enforce least privilege between WordPress and Postgres, isolate namespaces. citeturn15search1  

### Rollback and cleanup plan

#### Remove workloads but keep cluster

```bash
kubectl delete -f apps/manifests/40-ingress.yaml
kubectl delete -f apps/manifests/30-networkpolicies.yaml
kubectl delete -f apps/manifests/20-dev.yaml
kubectl delete -f apps/manifests/21-test.yaml
kubectl delete -f apps/manifests/22-acc.yaml
```

If you delete PVCs, local PV reclaim policy `Retain` keeps data until you deliberately remove PVs/directories.

#### Reset Kubernetes on the VPS

The kubeadm create-cluster docs describe cleanup with `kubeadm reset` and note it does not remove iptables rules/IPVS tables; manual flushing may be required. citeturn26view0  

```bash
sudo kubeadm reset -f
sudo iptables -F && sudo iptables -t nat -F && sudo iptables -t mangle -F && sudo iptables -X
```

#### Terraform destroy (deprovision infrastructure)

From the remote PC:

```bash
cd repo/infra
terraform destroy
```

If you created floating IPs or other network assets, they will be destroyed if managed in your Terraform configuration (floating IP resources and association resources support import and lifecycle management). citeturn20view0turn11view0  

### Deployment flow diagram

```mermaid
flowchart LR
  A[Remote PC: terraform apply (OpenStack)] --> B[VPS created + security groups + floating IP]
  B --> C[SSH to VPS]
  C --> D[Install container runtime + kubeadm/kubelet/kubectl]
  D --> E[kubeadm init]
  E --> F[Install Calico]
  F --> G[Remove control-plane taint for single-node scheduling]
  G --> H[Install ingress-nginx (hostNetwork)]
  H --> I[Apply StorageClass + PVs + PVCs]
  I --> J[Create namespaces dev/test/acc]
  J --> K[Deploy PostgreSQL + WordPress per namespace]
  K --> L[Apply ingress + NetworkPolicies]
  L --> M[Validation: kubectl get, curl hosts, probes]
  M --> N[Ops: backups (CronJob + pg_dump), metrics-server, logging approach]
```