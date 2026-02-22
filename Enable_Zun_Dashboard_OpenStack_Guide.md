# Enabling Zun Dashboard in OpenStack Horizon
**Complete Step-by-Step Guide**

*Date: February 22, 2026*  
*System: BlueHarvest AI OpenStack Infrastructure*  
*OpenStack Release: 2023.2 (Bobcat)*

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [What is Zun?](#what-is-zun)
4. [Configuration Steps](#configuration-steps)
5. [Verification](#verification)
6. [Accessing Zun Dashboard](#accessing-zun-dashboard)
7. [Managing Containers](#managing-containers)
8. [Troubleshooting](#troubleshooting)
9. [CLI Alternative](#cli-alternative)

---

## Overview

This guide documents the process of enabling the Zun Dashboard panel in OpenStack Horizon, allowing web-based management of containers through the OpenStack dashboard interface.

### What Was Accomplished

✅ Enabled Zun dashboard in Kolla-Ansible configuration  
✅ Reconfigured Horizon container with Zun support  
✅ Verified Zun panel availability in dashboard  
✅ Enabled web-based container management  

### Time Required

- Configuration: 5 minutes
- Reconfiguration: 5-10 minutes
- Total: ~15 minutes

---

## Prerequisites

### Required Services

Before enabling Zun dashboard, ensure these services are already running:

```bash
# Check if Zun services are running
docker ps | grep -E "zun|kuryr|etcd"
```

**Expected Output:**
```
zun_compute                 Up X hours (healthy)
zun_cni_daemon              Up X hours (healthy)
zun_wsproxy                 Up X hours (healthy)
zun_api                     Up X hours (healthy)
kuryr                       Up X hours (healthy)
etcd                        Up X hours
```

### Required Configuration

In `/etc/kolla/globals.yml`, you must already have:

```yaml
enable_zun: "yes"
enable_kuryr: "yes"
enable_etcd: "yes"
```

If these are not enabled, Zun dashboard won't work even if you enable it.

---

## What is Zun?

### Service Description

**Zun** is OpenStack's container service that provides an API for running application containers without managing servers. Think of it as "containers-as-a-service" for OpenStack.

### Key Features

- ✅ **Container Lifecycle Management** - Create, start, stop, delete containers
- ✅ **Image Management** - Pull and manage container images
- ✅ **Resource Allocation** - Specify CPU, memory, storage for containers
- ✅ **Network Integration** - Containers on Neutron networks via Kuryr
- ✅ **Security Groups** - Apply OpenStack security policies to containers
- ✅ **Capsules** - Multi-container deployments (like Kubernetes pods)

### Use Cases

**Common scenarios where Zun is used:**

1. **Self-Hosted Applications** - Running services like Ollama, databases, web servers
2. **Microservices** - Deploying containerized microservices architecture
3. **CI/CD Pipelines** - Running build and test containers
4. **Batch Processing** - Executing containerized batch jobs
5. **Development Environments** - Providing isolated dev/test containers

---

## Configuration Steps

### Step 1: Check Current Configuration

First, verify your current Kolla-Ansible configuration:

```bash
# Navigate to the configuration file
cat /etc/kolla/globals.yml | grep -i zun
```

**Expected Output (if Zun is enabled):**
```yaml
enable_zun: "yes"
enable_kuryr: "yes"
enable_etcd: "yes"
enable_zun_dashboard: "yes"  # This might be missing
```

---

### Step 2: Enable Zun Dashboard (if not already enabled)

If `enable_zun_dashboard` is not set to "yes", add it:

```bash
# Edit globals.yml
nano /etc/kolla/globals.yml
```

**Add this line:**
```yaml
enable_zun_dashboard: "yes"
```

**Or append it via command:**
```bash
echo 'enable_zun_dashboard: "yes"' >> /etc/kolla/globals.yml
```

**Verify it was added:**
```bash
grep enable_zun_dashboard /etc/kolla/globals.yml
```

**Expected Output:**
```yaml
enable_zun_dashboard: "yes"
```

---

### Step 3: Activate Kolla-Ansible Virtual Environment

Kolla-Ansible commands must be run from within the virtual environment:

```bash
# Activate the virtual environment
source ~/kolla-deployment/kolla-venv/bin/activate
```

**Verify activation:**
```bash
# Check if kolla-ansible is available
which kolla-ansible
```

**Expected Output:**
```
/root/kolla-deployment/kolla-venv/bin/kolla-ansible
```

---

### Step 4: Reconfigure Horizon

Reconfigure only the Horizon service to apply the Zun dashboard changes:

```bash
# Navigate to the correct directory
cd /root/kolla-deployment/kolla-venv/share/kolla-ansible/ansible/inventory

# Reconfigure Horizon with Zun dashboard
kolla-ansible -i all-in-one reconfigure --tags horizon
```

**What This Command Does:**
- Reads `/etc/kolla/globals.yml` configuration
- Detects `enable_zun_dashboard: "yes"`
- Updates Horizon container environment variables
- Copies Zun dashboard panel files into Horizon
- Restarts Horizon container with new configuration

---

### Step 5: Monitor Reconfiguration Progress

The reconfiguration process will show detailed output. Look for these key indicators:

**Successful Tasks:**
```
TASK [horizon : Ensuring config directories exist] ******* ok
TASK [horizon : Copying over local_settings] ************ ok
TASK [horizon : Deploy horizon container] *************** changed
```

**Zun Enabled Confirmation:**
```
'environment': {
    ...
    'ENABLE_ZUN': 'yes',
    ...
}
```

**Final Result:**
```
PLAY RECAP *******************************************
localhost    : ok=27   changed=2   unreachable=0   failed=0
```

**Key Metrics:**
- `ok`: Number of successful tasks
- `changed`: Number of tasks that made changes (should be 1-2)
- `failed`: Must be 0

---

### Step 6: Wait for Horizon Restart

After reconfiguration, Horizon container needs time to fully restart:

```bash
# Wait for container to restart
sleep 30

# Check Horizon container status
docker ps | grep horizon
```

**Expected Output:**
```
horizon   Up X seconds (healthy)   0.0.0.0:80->80/tcp
```

**Note:** Status should show `(healthy)` after 30-60 seconds.

---

### Step 7: Verify Dashboard Access

Test that Horizon is accessible:

```bash
# Test HTTP access
curl -I http://cloud.blueharvestai.com

# Or HTTPS if configured
curl -I https://cloud.blueharvestai.com
```

**Expected Output:**
```
HTTP/1.1 200 OK
Server: Apache
```

Or:
```
HTTP/1.1 302 Found
Location: /dashboard/
```

Both responses indicate Horizon is working.

---

## Verification

### Verify Zun Dashboard Panel Installation

Check if Zun dashboard files were installed in the Horizon container:

```bash
# Check for Zun dashboard files
docker exec horizon ls -la /var/lib/kolla/venv/lib/python3.10/site-packages/ | grep zun
```

**Expected Output:**
```
drwxr-xr-x  zun_ui
```

---

### Check Enabled Panels

Verify Zun panels are in the enabled directory:

```bash
# List enabled dashboard panels
docker exec horizon ls -la /etc/openstack-dashboard/enabled/ | grep zun
```

**Expected Output:**
```
_2330_admin_container_capsules_panel.py
_2331_admin_container_capsules_panel.pyc
_2332_admin_container_containers_panel.py
_2333_admin_container_containers_panel.pyc
```

---

### Check Horizon Container Environment

Verify the Horizon container has Zun enabled in its environment:

```bash
# Check container environment variables
docker inspect horizon | grep -A 20 "Env"
```

**Look for:**
```json
"Env": [
    ...
    "ENABLE_ZUN=yes",
    ...
]
```

---

## Accessing Zun Dashboard

### Login to Dashboard

**URL:**
```
https://cloud.blueharvestai.com
```

**Credentials:**
- Username: `admin`
- Password: Found in `/etc/kolla/passwords.yml`

**Get Password:**
```bash
grep keystone_admin_password /etc/kolla/passwords.yml
```

---

### Navigate to Zun Panel

Once logged in to Horizon:

**Path 1: Via Menu**
```
Project → Container → Containers
```

**Path 2: Direct URL**
```
https://cloud.blueharvestai.com/project/containers
```

---

### Dashboard Interface Overview

The Zun Container dashboard includes these sections:

#### **Containers Tab**

**Columns:**
- Container Name
- Image
- Status (Running, Stopped, Error)
- Task State (Creating, Running, Stopped)
- CPU/Memory
- Actions (Start, Stop, Restart, Delete, Console, Logs)

**Actions Available:**
- ✅ **Create Container** - Launch new containers
- ✅ **Start** - Start stopped containers
- ✅ **Stop** - Stop running containers
- ✅ **Restart** - Restart containers
- ✅ **Delete** - Remove containers
- ✅ **View Logs** - Show container logs
- ✅ **Open Console** - Interactive terminal

#### **Capsules Tab**

Manage multi-container deployments (similar to Kubernetes pods).

#### **Images Tab**

View and manage container images available for deployment.

---

## Managing Containers

### View Container Details

**Steps:**
1. Navigate to **Project → Container → Containers**
2. Click on container name (e.g., Ollama container)
3. View detailed information:
   - Container ID
   - Image used
   - Status and state
   - Resource allocation (CPU, RAM)
   - Network configuration
   - Creation time
   - Runtime details

---

### Restart a Container

**Method 1: Via Dashboard**

1. Navigate to **Project → Container → Containers**
2. Find the container (e.g., Ollama)
3. Click **Actions** dropdown
4. Select **Restart**
5. Confirm the action
6. Wait 10-30 seconds for restart
7. Refresh page to see updated status

**Method 2: Batch Restart**

1. Select multiple containers using checkboxes
2. Click **More Actions** at top
3. Select **Restart Containers**
4. Confirm

---

### View Container Logs

**Steps:**
1. Navigate to container list
2. Click **Actions** → **View Logs**
3. Logs display in modal window
4. Use **Refresh** button to update
5. Logs show last 50-100 lines by default

**Example Logs:**
```
2026-02-22 10:30:15 INFO Starting Ollama server
2026-02-22 10:30:16 INFO Listening on 0.0.0.0:11434
2026-02-22 10:30:17 INFO Ready to serve requests
```

---

### Stop/Start Container

**Stop Container:**
1. Navigate to container list
2. Click **Actions** → **Stop**
3. Container status changes to "Stopped"

**Start Container:**
1. Find stopped container
2. Click **Actions** → **Start**
3. Container status changes to "Running"

---

### Create New Container

**Steps:**
1. Click **Create Container** button
2. Fill in form:
   - **Container Name**: `my-container`
   - **Image**: `nginx:latest` or `ollama/ollama:latest`
   - **CPU**: Number of cores (e.g., 2)
   - **Memory**: RAM in MB (e.g., 4096)
   - **Command**: Optional startup command
3. Configure networking (optional)
4. Set security groups (optional)
5. Click **Create**

**Container starts automatically after creation.**

---

## Troubleshooting

### Zun Panel Not Visible

**Symptom:** Container section missing from dashboard menu

**Solutions:**

**1. Verify Configuration:**
```bash
grep enable_zun_dashboard /etc/kolla/globals.yml
```

Should show: `enable_zun_dashboard: "yes"`

**2. Force Horizon Restart:**
```bash
docker restart horizon
sleep 30
```

**3. Check Horizon Logs:**
```bash
docker logs horizon --tail 50
```

Look for errors related to Zun or dashboard panels.

**4. Verify Zun Services Running:**
```bash
docker ps | grep zun
```

All Zun services must be healthy.

---

### Container Actions Fail

**Symptom:** Start/Stop/Restart buttons don't work or show errors

**Solutions:**

**1. Check Zun API:**
```bash
docker logs zun_api --tail 50
```

**2. Verify Kuryr Network:**
```bash
docker logs kuryr --tail 50
```

**3. Check OpenStack Services:**
```bash
source /etc/kolla/admin-openrc.sh
openstack service list | grep zun
```

**Expected:**
```
| <id> | zun      | container | enabled |
| <id> | zun-api  | container | enabled |
```

---

### Permission Errors

**Symptom:** "You are not authorized to access this resource"

**Solutions:**

**1. Check User Role:**

User must have appropriate role (typically `admin` or `member`).

**2. Verify Policy Configuration:**
```bash
docker exec horizon cat /etc/openstack-dashboard/zun_policy.yaml
```

**3. Check Keystone Authentication:**
```bash
source /etc/kolla/admin-openrc.sh
openstack token issue
```

---

## CLI Alternative

While the dashboard provides a graphical interface, you can also manage Zun containers via CLI:

### List Containers

```bash
# Source OpenStack credentials
source /etc/kolla/admin-openrc.sh

# List all Zun containers
openstack appcontainer list
```

**Or via Docker (for Zun-managed containers):**
```bash
docker ps -a | grep zun-
```

---

### Get Container Details

```bash
# Get container UUID from docker ps
docker ps -a | grep ollama

# Example output:
# 172daf97e4cd   ollama/ollama:latest   ...   zun-c5d7d35c-05c9-40e4-a5d4-a8c8c3eff1c3

# The UUID is: c5d7d35c-05c9-40e4-a5d4-a8c8c3eff1c3
# Show container details
openstack appcontainer show c5d7d35c-05c9-40e4-a5d4-a8c8c3eff1c3
```

---

### Restart Container via CLI

```bash
# Restart by Zun UUID
openstack appcontainer restart c5d7d35c-05c9-40e4-a5d4-a8c8c3eff1c3

# Or by Docker container ID
docker restart 172daf97e4cd
```

---

### View Container Logs via CLI

```bash
# Via Zun
openstack appcontainer logs show c5d7d35c-05c9-40e4-a5d4-a8c8c3eff1c3

# Via Docker
docker logs 172daf97e4cd --tail 50
```

---

### Stop/Start via CLI

```bash
# Stop container
openstack appcontainer stop c5d7d35c-05c9-40e4-a5d4-a8c8c3eff1c3

# Start container
openstack appcontainer start c5d7d35c-05c9-40e4-a5d4-a8c8c3eff1c3

# Check status
openstack appcontainer list
```

---

## Configuration Reference

### Complete globals.yml Settings

**Minimal Zun Configuration:**
```yaml
# Container service (Zun)
enable_zun: "yes"
enable_kuryr: "yes"
enable_etcd: "yes"
enable_zun_dashboard: "yes"
```

**Full Zun Configuration (with optional settings):**
```yaml
# Zun - Container Service
enable_zun: "yes"
enable_zun_dashboard: "yes"

# Kuryr - Container Networking
enable_kuryr: "yes"

# Etcd - Distributed Key-Value Store
enable_etcd: "yes"

# Optional: Zun-specific settings
zun_docker_runtime: "docker"
zun_capsule_driver: "default"

# Network settings
neutron_plugin_agent: "openvswitch"
```

---

### Kolla-Ansible Commands Reference

**Reconfigure Specific Service:**
```bash
# Reconfigure only Horizon
kolla-ansible -i all-in-one reconfigure --tags horizon

# Reconfigure only Zun
kolla-ansible -i all-in-one reconfigure --tags zun

# Reconfigure both
kolla-ansible -i all-in-one reconfigure --tags horizon,zun
```

**Deploy Full Stack:**
```bash
# Deploy all enabled services
kolla-ansible -i all-in-one deploy
```

**Restart Services:**
```bash
# Restart Horizon
docker restart horizon

# Restart all Zun services
docker restart zun_api zun_compute zun_wsproxy
```

---

## Best Practices

### 1. Always Use Virtual Environment

```bash
# Activate before any kolla-ansible command
source ~/kolla-deployment/kolla-venv/bin/activate
```

---

### 2. Backup Configuration Before Changes

```bash
# Backup globals.yml
cp /etc/kolla/globals.yml /etc/kolla/globals.yml.backup.$(date +%Y%m%d)

# Backup all Kolla config
tar -czf /root/kolla-backup-$(date +%Y%m%d).tar.gz /etc/kolla/
```

---

### 3. Verify Changes Before Deploying

```bash
# Check configuration syntax
kolla-ansible -i all-in-one prechecks

# Dry-run (check what would change)
kolla-ansible -i all-in-one reconfigure --tags horizon --check
```

---

### 4. Monitor Logs During Changes

```bash
# In separate terminal, watch Horizon logs
docker logs -f horizon

# Then run reconfigure in another terminal
```

---

### 5. Incremental Changes

**Instead of:**
```bash
# Don't reconfigure everything at once
kolla-ansible -i all-in-one reconfigure
```

**Do:**
```bash
# Reconfigure only what changed
kolla-ansible -i all-in-one reconfigure --tags horizon
```

This minimizes downtime and risk.

---

## Summary

### What Was Configured

✅ **Zun Dashboard Panel** - Added to Horizon  
✅ **Container Management UI** - Web interface for Zun  
✅ **Horizon Reconfiguration** - Applied changes without full redeployment  

### Key Files Modified

- `/etc/kolla/globals.yml` - Added `enable_zun_dashboard: "yes"`
- Horizon container - Reconfigured with Zun panels

### Services Affected

- **Horizon** - Restarted with new configuration
- **Zun** - No changes (already running)

### Time Required

- Configuration: 2 minutes
- Reconfiguration: 5-10 minutes
- Verification: 3 minutes
- **Total: ~15 minutes**

---

## Next Steps

After enabling Zun dashboard, you can:

1. **Manage Existing Containers** - Start/stop/restart Ollama and other containers
2. **Deploy New Containers** - Launch additional services via dashboard
3. **Monitor Resources** - Track CPU/memory usage of containers
4. **Configure Networks** - Attach containers to Neutron networks
5. **Set Up Capsules** - Deploy multi-container applications

---

## Additional Resources

**Official Documentation:**
- OpenStack Zun: https://docs.openstack.org/zun/latest/
- Kolla-Ansible: https://docs.openstack.org/kolla-ansible/latest/
- Horizon: https://docs.openstack.org/horizon/latest/

**BlueHarvest AI Documentation:**
- OpenStack Architecture Guide
- Docker & OpenStack Troubleshooting Guide
- DNS Configuration Guide

---

## Appendix: Quick Reference Commands

### Enable Zun Dashboard
```bash
echo 'enable_zun_dashboard: "yes"' >> /etc/kolla/globals.yml
source ~/kolla-deployment/kolla-venv/bin/activate
cd /root/kolla-deployment/kolla-venv/share/kolla-ansible/ansible/inventory
kolla-ansible -i all-in-one reconfigure --tags horizon
```

### Verify Setup
```bash
docker ps | grep horizon
curl -I https://cloud.blueharvestai.com
docker exec horizon ls /etc/openstack-dashboard/enabled/ | grep zun
```

### Access Dashboard
```
URL: https://cloud.blueharvestai.com
Path: Project → Container → Containers
```

### Manage Containers
```bash
# CLI method
source /etc/kolla/admin-openrc.sh
openstack appcontainer list
openstack appcontainer restart <UUID>

# Docker method
docker ps -a | grep zun-
docker restart <CONTAINER_ID>
```

---

**Document Version:** 1.0  
**Last Updated:** February 22, 2026  
**Author:** BlueHarvest AI Operations Team  
**Status:** Complete and Verified

---

*This guide documents the actual process used to enable Zun dashboard on the BlueHarvest AI OpenStack infrastructure. All commands and outputs are real and tested.*
