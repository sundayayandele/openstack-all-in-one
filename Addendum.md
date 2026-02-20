Addendum: cert-manager + external-dns + Cinder CSI + GitLab GitOps
Date: 2026-02-20
Add-ons: cert-manager + external-dns + Cinder CSI + GitLab GitOps
**Date:** 2026-02-20

This add-on pack makes your platform **production-grade**:
- TLS automation with **cert-manager** + **Let’s Encrypt**
- DNS automation with **external-dns**
- Durable storage on OpenStack via **Cinder CSI**
- GitOps repository and CI using **GitLab**, with Argo CD syncing from GitLab

---

1) cert-manager (Let’s Encrypt)
Install
Already included via Terraform Helm release (`terraform/kubernetes/main.tf`).

Configure ClusterIssuer
Edit:
- `k8s/addons/cert-manager/clusterissuer-letsencrypt.yaml`
Set your email and apply:
```bash
kubectl apply -f k8s/addons/cert-manager/clusterissuer-letsencrypt.yaml
```

Ingress TLS
Ingress manifests in each env already include:
- `cert-manager.io/cluster-issuer: letsencrypt-prod`
- `spec.tls` section

> Ensure DNS points to your Floating IP before requesting certificates.

---

2) external-dns (DNS automation)
Recommended approach
Use Cloudflare (simple + reliable) or your DNS provider.

Install
Included via Terraform Helm release.

Create secret
```bash
kubectl apply -f k8s/addons/external-dns/secret-cloudflare-template.yaml
```

Domain filters (important)
Edit `terraform/kubernetes/values/external-dns-values.yaml`:
```yaml
domainFilters:
  - example.com
```
This prevents accidental modification outside your domain.

---

3) OpenStack Cinder CSI (durable PVC)
What you get
- PostgreSQL data stored on Cinder volumes
- WordPress uploads stored on Cinder volumes (`wp-uploads` PVC)

Prerequisites
1. Your OpenStack must have **Cinder** enabled and a working volume type.
2. Kubernetes nodes must reach the OpenStack endpoints (usually via the tenant network router).

Create OpenStack cloud config secret (kube-system)
Create a `clouds.yaml` (example):
```yaml
clouds:
  openstack:
    auth:
      auth_url: https://YOUR_OS_AUTH_URL
      username: YOUR_USER
      password: YOUR_PASS
      project_name: YOUR_PROJECT
      user_domain_name: Default
      project_domain_name: Default
    region_name: RegionOne
    interface: public
    identity_api_version: 3
```
Apply secret:
```bash
kubectl -n kube-system create secret generic cloud-config --from-file=clouds.yaml=clouds.yaml
```

StorageClass
Apply:
```bash
kubectl apply -f k8s/addons/cinder/storageclass-cinder.yaml
```

Now PostgreSQL + WordPress uploads PVCs will bind to Cinder volumes.

---

4) GitLab GitOps (instead of GitHub)
What changes
- Host this repo in GitLab (self-managed or gitlab.com)
- Use `.gitlab-ci.yml` for validation
- Argo CD pulls manifests from GitLab

Steps
1. Create a GitLab project and push repo.
2. Update Argo CD repo URLs:
   - `argocd/root-app.yaml`
   - `argocd/apps/*.yaml`
   Replace repoURL with your GitLab repo URL.

3. Add Argo CD credentials secret:
```bash
kubectl apply -f argocd/gitlab-repo-credential-template.yaml
```

4. Protect branches + require Merge Requests:
- main branch protected
- approvals enabled
- optional: signed commits

Recommended GitOps flow
- Developers open MR → CI validates → merge → Argo CD syncs automatically

---

5) Production notes
- Move Secrets to Sealed Secrets or Vault (Phase 2)
- Enable cert-manager metrics + alerts
- Consider OpenStack Designate provider for external-dns if your environment uses it

---
