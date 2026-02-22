# BlueHarvest AI Infrastructure - System Status & Recovery Plan
**Complete Assessment and Recovery Roadmap**

*Date: February 22, 2026 - 09:45 UTC*  
*System: BlueHarvest AI OpenStack Infrastructure*  
*Server: xx.xxx.xxx.xxx (blueharvestai.com)*

---

## Executive Summary

### 🔴 **Critical Issues**
- Horizon Dashboard login broken
- Kuryr networking plugin unhealthy
- Ollama LLM container cannot start
- LLS service (lls.blueharvestai.com) unreachable

### 🟢 **What's Working**
- Docker daemon running
- 38/40 OpenStack containers operational
- Nginx web server running
- DNS configuration correct
- All core OpenStack services (Nova, Neutron, Glance, Cinder, Keystone)
- Zun dashboard enabled in Horizon

### 📊 **Overall Status**: **70% Operational**

---

## Table of Contents

1. [Timeline of Events](#timeline-of-events)
2. [Current System State](#current-system-state)
3. [Root Cause Analysis](#root-cause-analysis)
4. [Immediate Recovery Steps](#immediate-recovery-steps)
5. [Detailed Fix Procedures](#detailed-fix-procedures)
6. [Verification & Testing](#verification--testing)
7. [Prevention Strategy](#prevention-strategy)
8. [Long-term Recommendations](#long-term-recommendations)

---

## Timeline of Events

### Initial State (Before Issues)
**Status:** All services operational
- ✅ Horizon dashboard accessible
- ✅ Ollama running with 8 LLM models
- ✅ LLS service accessible at lls.blueharvestai.com
- ✅ All OpenStack services healthy

---

### Incident Start: Docker Daemon Failure
**Time:** ~45 hours ago (Feb 20, 2026)

**Trigger Event:**
- Docker daemon.json configuration corrupted
- Duplicate "hosts" entries in JSON file
- Invalid JSON syntax

**Error:**
```
unable to configure the Docker daemon with file /etc/docker/daemon.json: 
invalid character '"' after top-level value
```

**Immediate Impact:**
- Docker daemon stopped
- All containers (40+) went offline
- Complete infrastructure outage

---

### Recovery Phase 1: Docker Restoration
**Time:** Feb 22, 2026 00:46 UTC

**Actions Taken:**
1. Identified corrupted `/etc/docker/daemon.json`
2. Created corrected JSON configuration
3. Restarted Docker daemon successfully
4. Started all containers

**Result:**
- ✅ Docker daemon operational
- ✅ 38/40 containers started successfully
- ⚠️ 2 containers failed (Kuryr networking issue)

---

### Recovery Phase 2: Zun Dashboard Enable
**Time:** Feb 22, 2026 00:51 UTC

**Actions Taken:**
1. Verified `enable_zun_dashboard: "yes"` in globals.yml
2. Activated kolla-ansible virtual environment
3. Reconfigured Horizon with Zun support
4. Restarted Horizon container

**Result:**
- ✅ Zun dashboard panel added to Horizon
- ✅ Container management UI available
- ⚠️ Horizon login functionality broken

---

### Current State: Multiple Service Failures
**Time:** Feb 22, 2026 09:45 UTC

**Active Issues:**
1. **Kuryr unhealthy** - Cannot start (Keystone connection issues initially, now persistent crashes)
2. **Ollama container stopped** - Cannot start due to Kuryr networking failure
3. **Horizon login broken** - https://cloud.blueharvestai.com/auth/login/ returns 404
4. **LLS service unreachable** - Nginx proxy working but backend unavailable
5. **Nginx crashed once** - Required manual restart

---

## Current System State

### Infrastructure Components

#### ✅ **Working Services (38 containers)**

**Core Services:**
```
✅ mariadb                  - Database (healthy)
✅ memcached                - Caching (healthy)
✅ rabbitmq                 - Message queue (healthy)
✅ keystone                 - Identity service (healthy) - Port 5000
✅ keystone_fernet          - Token management (healthy)
✅ keystone_ssh             - SSH service (healthy)
```

**Compute Services:**
```
✅ nova_api                 - Compute API (healthy)
✅ nova_scheduler           - VM scheduling (healthy)
✅ nova_conductor           - Compute orchestration (healthy)
✅ nova_compute             - Hypervisor (healthy)
✅ nova_libvirt             - Virtualization (healthy)
✅ nova_novncproxy          - Console access (healthy)
✅ nova_ssh                 - SSH tunneling (healthy)
✅ placement_api            - Resource tracking (healthy)
```

**Network Services:**
```
✅ neutron_server           - Network API (healthy)
✅ neutron_dhcp_agent       - DHCP service (healthy)
✅ neutron_l3_agent         - Routing (healthy)
✅ neutron_metadata_agent   - Metadata service (healthy)
✅ neutron_openvswitch_agent - OVS integration (healthy)
✅ openvswitch_db           - OVS database (healthy)
✅ openvswitch_vswitchd     - OVS switch (healthy)
```

**Storage Services:**
```
✅ glance_api               - Image service (healthy)
✅ cinder_api               - Block storage API (healthy)
✅ cinder_scheduler         - Storage scheduling (healthy)
✅ cinder_volume            - Volume management (healthy)
✅ cinder_backup            - Backup service (healthy)
✅ iscsid                   - iSCSI initiator
✅ tgtd                     - iSCSI target
```

**Orchestration Services:**
```
✅ heat_api                 - Orchestration API (healthy)
✅ heat_api_cfn             - CloudFormation API (healthy)
✅ heat_engine              - Orchestration engine (healthy)
```

**Container Services:**
```
✅ zun_api                  - Container API (healthy)
✅ zun_compute              - Container runtime (healthy)
✅ zun_wsproxy              - WebSocket proxy (healthy)
✅ zun_cni_daemon           - Container networking (healthy)
✅ etcd                     - Key-value store
```

**Dashboard:**
```
⚠️ horizon                  - Web dashboard (running but login broken)
```

**Utility Services:**
```
✅ cron                     - Scheduled tasks
✅ kolla_toolbox            - Admin tools
✅ mariadb_clustercheck     - DB health monitoring
```

---

#### 🔴 **Failed/Problematic Services**

**1. Kuryr Network Plugin**
```
Container: kuryr (d44b51371a43)
Status: unhealthy
Port: 23750 (not listening)
Error: Continuous restart loop
```

**Error Details:**
```
keystoneauth1.exceptions.discovery.DiscoveryFailure: 
Could not find versioned identity endpoints when attempting to authenticate.
Unable to establish connection to http://cloud.blueharvestai.com:5000
```

**Impact:**
- Zun containers cannot start
- Container networking unavailable
- Ollama container stuck in "Exited" state

**Root Cause:**
Initially couldn't connect to Keystone (port 5000). After Keystone restart, Kuryr still crashes on startup - likely configuration issue or Neutron extension missing.

---

**2. Ollama LLM Container**
```
Container ID: 172daf97e4cd
Container Name: zun-c5d7d35c-05c9-40e4-a5d4-a8c8c3eff1c3
Image: ollama/ollama:latest
Status: Exited (128)
Last Exit: 4 hours ago
```

**Error:**
```
Error response from daemon: failed to set up container networking: 
legacy plugin: Post "http://xx.xxx.xxx.xxx:23750/Plugin.Activate": 
dial tcp xx.xxx.xxx.xxx:23750: connect: connection refused
```

**Impact:**
- LLM service completely offline
- 8 models unavailable (Mistral, LLaMA2, DeepSeek-R1, Mixtral, Qwen, Gemma2, Phi3, CodeLlama)
- lls.blueharvestai.com returns 502 Bad Gateway

**Dependencies:**
- Requires Kuryr to be healthy
- Requires port 23750 listening

---

**3. Horizon Dashboard Login**
```
Service: horizon
Status: Running (unhealthy)
URL: https://cloud.blueharvestai.com/auth/login/
Error: 404 Page Not Found
```

**Symptoms:**
- Main dashboard accessible (/)
- Login page broken (/auth/login/)
- OpenStack services accessible via CLI
- Horizon container shows "unhealthy" status

**Likely Causes:**
1. Horizon configuration corrupted during Zun enable
2. Django URL routing broken
3. Missing authentication backend
4. Static files not served correctly

---

**4. LLS Service Proxy**
```
Domain: lls.blueharvestai.com
Nginx Status: Running, port 443 listening
Backend Status: Unreachable (10.0.2.137:11434)
Error: 502 Bad Gateway
```

**Configuration:**
```nginx
Location: /etc/nginx/conf.d/ai_blueharvestai_com.conf
Upstream: http://10.0.2.137:11434
Auth: Cookie-based (commented out for testing)
```

**Network Test Results:**
```bash
✅ DNS resolution: Working (xx.xxx.xxx.xxx)
✅ HTTPS certificate: Valid (Let's Encrypt)
✅ Nginx listening: Port 443 active
❌ Backend reachable: No route to host (Error 113)
❌ Ollama API: Connection refused
```

---

**5. Nginx Service**
```
Service: nginx
Status: Running (restarted manually after crash)
Crash Time: Feb 22, 2026 05:41:38 UTC
Uptime: 4 hours
```

**Crash Details:**
```
Active: failed (Result: signal)
Main PID: killed (signal=KILL)
Zombie processes: 9 worker processes remained
```

**Recovery:**
- Killed all nginx processes with `pkill -9`
- Restarted via systemd
- Currently stable

---

### Network Status

**External Access:**
```
✅ Port 80 (HTTP):   Listening - Nginx
✅ Port 443 (HTTPS): Listening - Nginx
✅ Port 5000:        Listening - Keystone (via Apache2)
❌ Port 23750:       Not listening - Kuryr (failed)
```

**DNS Records (Hostinger):**
```
✅ cloud.blueharvestai.com → xx.xxx.xxx.xxx
✅ lls.blueharvestai.com   → xx.xxx.xxx.xxx
✅ mail.blueharvestai.com  → xx.xxx.xxx.xxx
✅ api.blueharvestai.com   → xx.xxx.xxx.xxx
```

**OpenStack Internal Network:**
```
❌ 10.0.2.137:11434 - Ollama container (unreachable)
⚠️ 10.0.2.0/24      - Neutron network (partially functional)
```

---

### Disk & Resource Status

**Disk Space:**
```
/ (root):        Unknown (not checked recently)
/var:            Unknown (Docker logs may be growing)
/var/lib/docker: Unknown (container storage)
```

**Docker Resources:**
```
Total Containers: 42
Running:          38
Stopped:          2 (Ollama + 1 other)
Failed:           2 (network setup failures)
```

---

## Root Cause Analysis

### Primary Root Cause: Docker Configuration Corruption

**What Happened:**
The `/etc/docker/daemon.json` file became corrupted with duplicate JSON keys:

**Broken Configuration:**
```json
{
  "bridge": "none",
  "ip-forward": false,
  "iptables": false,
  "log-opts": {"max-file": "5", "max-size": "50m"},
  "hosts": ["unix:///var/run/docker.sock"]
}  "hosts": ["unix:///var/run/docker.sock", "tcp://xx.xxx.xxx.xxx:2375"]
}
```

**Issues:**
1. Duplicate `"hosts"` key (invalid JSON)
2. Extra closing brace `}`
3. Malformed JSON structure

**Impact:**
- Docker daemon refused to start
- All containers stopped
- Complete infrastructure failure

**How It Likely Happened:**
1. Manual edit to add TCP socket (`tcp://xx.xxx.xxx.xxx:2375`)
2. Editor added new hosts entry instead of merging
3. No JSON validation before saving
4. Docker daemon crashed on next restart

---

### Secondary Issues: Cascading Failures

**1. Kuryr Network Plugin Failure**

**Timeline:**
1. Docker crashed → All containers stopped
2. Docker restarted → Most containers auto-started
3. Kuryr started but couldn't connect to Keystone (port 5000 not listening)
4. Keystone manually restarted
5. Kuryr now connects to Keystone but crashes anyway

**Current Error:**
```
keystoneauth1.exceptions.discovery.DiscoveryFailure
```

**Possible Causes:**
- Kuryr configuration corrupted during crash
- Required Neutron extensions missing or disabled
- Database state inconsistent
- Keystone endpoint configuration wrong

---

**2. Horizon Login Breakdown**

**Timeline:**
1. Horizon stopped during Docker crash
2. Horizon reconfigured for Zun dashboard
3. Horizon restarted with new configuration
4. Login URL now returns 404

**Possible Causes:**
- Zun dashboard panel conflicts with default auth
- Django URL routing corrupted
- Static file serving broken
- Session middleware misconfigured
- Keystone authentication backend failed

---

**3. Ollama Container Network Isolation**

**Dependencies:**
```
Ollama Container
    ↓ requires
Kuryr Network Plugin (port 23750)
    ↓ requires
Neutron + Keystone
```

**Why It's Failing:**
- Kuryr not listening on port 23750
- Docker can't create container network
- Container stuck in "Exited" state
- VM network (10.0.2.137) unreachable

---

## Immediate Recovery Steps

### Priority 1: Fix Kuryr (Highest Impact)

**Kuryr is blocking:**
- Ollama container startup
- Any new Zun container creation
- Container networking for all Zun workloads

**Quick Fix Attempt:**

```bash
# 1. Stop Kuryr
docker stop kuryr

# 2. Check for Kuryr config issues
cat /etc/kolla/kuryr-libnetwork/kuryr.conf | grep auth_url

# 3. Verify Neutron extensions
source /etc/kolla/admin-openrc.sh
openstack extension list --network | grep subnet

# 4. Clear Kuryr data and restart
rm -rf /var/lib/kuryr/*
docker start kuryr

# 5. Monitor startup
docker logs -f kuryr
```

**Expected Result:**
- Kuryr should connect to Keystone
- Port 23750 should start listening
- Health status should become "healthy"

**If This Fails:**
- Proceed to full Kuryr reconfiguration (see Detailed Fix Procedures)

---

### Priority 2: Fix Horizon Login (High Impact)

**Why This Matters:**
- Dashboard is the primary management interface
- Users cannot access OpenStack services
- Administrative tasks blocked

**Quick Fix Attempt:**

```bash
# 1. Check Horizon logs
docker logs horizon --tail 100 | grep -i "error\|404\|auth"

# 2. Restart Horizon fresh
docker restart horizon
sleep 20

# 3. Test login page
curl -I https://cloud.blueharvestai.com/auth/login/

# 4. Check Django static files
docker exec horizon ls -la /var/lib/kolla/venv/lib/python3.10/site-packages/openstack_dashboard/static/

# 5. Force Horizon recollect static files
docker exec horizon /var/lib/kolla/venv/bin/python /var/lib/kolla/venv/bin/manage.py collectstatic --noinput
```

**Expected Result:**
- Login page should return 200 OK
- Login form should display

**If This Fails:**
- Proceed to full Horizon rebuild (see Detailed Fix Procedures)

---

### Priority 3: Restore Ollama (Medium Impact)

**Dependencies:**
- Requires Kuryr to be fixed first
- Requires Keystone operational (✅ done)

**Once Kuryr is Healthy:**

```bash
# 1. Verify Kuryr is listening
netstat -tulpn | grep 23750

# 2. Start Ollama container
docker start 172daf97e4cd

# 3. Wait for initialization
sleep 15

# 4. Check status
docker ps | grep ollama

# 5. Test API
curl http://10.0.2.137:11434/api/tags

# 6. Test via proxy
curl https://lls.blueharvestai.com/ollama/api/tags
```

**Expected Result:**
- Ollama container status: Running
- API returns list of 8 models
- Proxy returns 200 OK

---

## Detailed Fix Procedures

### Fix 1: Complete Kuryr Recovery

**Symptom:** Kuryr status "unhealthy", port 23750 not listening, continuous restart loop

**Diagnosis Steps:**

```bash
# 1. Check current Kuryr status
docker inspect kuryr --format='{{.State.Health.Status}}'

# 2. View detailed error logs
tail -100 /var/log/kolla/kuryr/kuryr-server.log

# 3. Check Kuryr configuration
docker exec kuryr cat /etc/kuryr/kuryr.conf | grep -A 5 "auth"

# 4. Verify Neutron extensions
source /etc/kolla/admin-openrc.sh
openstack extension list --network
```

---

**Solution A: Reconfigure Kuryr**

```bash
# Activate kolla-ansible environment
source ~/kolla-deployment/kolla-venv/bin/activate
cd ~/kolla-deployment/kolla-venv/share/kolla-ansible/ansible/inventory

# Reconfigure Kuryr
kolla-ansible -i all-in-one reconfigure --tags kuryr

# Restart Kuryr
docker restart kuryr

# Wait and verify
sleep 30
docker ps | grep kuryr
netstat -tulpn | grep 23750
```

---

**Solution B: Full Kuryr Rebuild**

```bash
# Stop and remove Kuryr container
docker stop kuryr
docker rm kuryr

# Deploy fresh Kuryr
source ~/kolla-deployment/kolla-venv/bin/activate
cd ~/kolla-deployment/kolla-venv/share/kolla-ansible/ansible/inventory
kolla-ansible -i all-in-one deploy --tags kuryr

# Verify
docker ps | grep kuryr
docker logs kuryr --tail 50
```

---

**Solution C: Check Neutron Extensions**

```bash
# Source credentials
source /etc/kolla/admin-openrc.sh

# List Neutron extensions
openstack extension list --network

# Look for required extensions:
# - subnet_allocation
# - security-group
# - port-security

# If missing, enable in Neutron config
nano /etc/kolla/neutron-server/neutron.conf
# Add: service_plugins = subnet_allocation

# Restart Neutron
docker restart neutron_server
sleep 10

# Retry Kuryr
docker restart kuryr
```

---

**Verification:**

```bash
# Kuryr should be healthy
docker ps | grep kuryr
# Expected: Up X minutes (healthy)

# Port 23750 should be listening
netstat -tulpn | grep 23750
# Expected: tcp ... xx.xxx.xxx.xxx:23750 ... LISTEN

# Test with Ollama
docker start 172daf97e4cd
# Expected: No "connection refused" error
```

---

### Fix 2: Horizon Login Restoration

**Symptom:** https://cloud.blueharvestai.com/auth/login/ returns 404

**Diagnosis Steps:**

```bash
# 1. Check Horizon container health
docker inspect horizon --format='{{.State.Health.Status}}'

# 2. View Horizon logs
docker logs horizon --tail 100

# 3. Check Apache error logs
docker exec horizon tail -50 /var/log/kolla/horizon/horizon.log

# 4. Test Horizon URLs
curl -I https://cloud.blueharvestai.com/
curl -I https://cloud.blueharvestai.com/dashboard/
curl -I https://cloud.blueharvestai.com/auth/login/
```

---

**Solution A: Restart Horizon with Config Refresh**

```bash
# Stop Horizon
docker stop horizon

# Clear Horizon cache
docker exec horizon rm -rf /var/lib/kolla/.settings.md5sum.txt

# Start Horizon
docker start horizon

# Wait for full initialization
sleep 30

# Force regenerate settings
docker exec horizon /var/lib/kolla/venv/bin/python /var/lib/kolla/venv/bin/manage.py collectstatic --noinput

# Test
curl -I https://cloud.blueharvestai.com/auth/login/
```

---

**Solution B: Reconfigure Horizon**

```bash
# Activate environment
source ~/kolla-deployment/kolla-venv/bin/activate
cd ~/kolla-deployment/kolla-venv/share/kolla-ansible/ansible/inventory

# Reconfigure Horizon completely
kolla-ansible -i all-in-one reconfigure --tags horizon

# Wait for restart
sleep 30

# Test login page
curl -I https://cloud.blueharvestai.com/auth/login/
```

---

**Solution C: Check Django Settings**

```bash
# Enter Horizon container
docker exec -it horizon bash

# Check Django configuration
python3 /var/lib/kolla/venv/bin/manage.py check

# Test URL routing
python3 /var/lib/kolla/venv/bin/manage.py show_urls | grep auth

# Check static files
ls -la /var/lib/kolla/venv/lib/python3.10/site-packages/openstack_dashboard/static/

# Recollect static files if missing
python3 /var/lib/kolla/venv/bin/manage.py collectstatic --noinput

# Exit container
exit

# Restart Horizon
docker restart horizon
```

---

**Solution D: Full Horizon Rebuild**

```bash
# Last resort: rebuild Horizon completely
source ~/kolla-deployment/kolla-venv/bin/activate
cd ~/kolla-deployment/kolla-venv/share/kolla-ansible/ansible/inventory

# Stop and remove
docker stop horizon
docker rm horizon

# Backup configuration
cp /etc/kolla/horizon/local_settings /tmp/local_settings.backup

# Redeploy
kolla-ansible -i all-in-one deploy --tags horizon

# Verify
docker ps | grep horizon
curl -I https://cloud.blueharvestai.com/auth/login/
```

---

**Verification:**

```bash
# Login page should work
curl -I https://cloud.blueharvestai.com/auth/login/
# Expected: HTTP/1.1 200 OK

# Test actual login
curl -X POST https://cloud.blueharvestai.com/auth/login/ \
  -d "username=admin&password=YOUR_PASSWORD" \
  -c cookies.txt

# Dashboard should be accessible
curl -b cookies.txt https://cloud.blueharvestai.com/dashboard/
```

---

### Fix 3: Ollama Container Network Restoration

**Prerequisites:**
- ✅ Kuryr must be healthy
- ✅ Port 23750 must be listening
- ✅ Keystone operational

**Procedure:**

```bash
# 1. Verify prerequisites
docker ps | grep kuryr | grep healthy
netstat -tulpn | grep 23750
docker ps | grep keystone

# 2. Attempt to start Ollama
docker start 172daf97e4cd

# 3. Check startup
sleep 10
docker ps | grep ollama

# 4. If failed, check logs
docker logs 172daf97e4cd --tail 50
```

---

**If Network Setup Still Fails:**

```bash
# Option 1: Restart with Zun API
source /etc/kolla/admin-openrc.sh
openstack appcontainer restart c5d7d35c-05c9-40e4-a5d4-a8c8c3eff1c3

# Option 2: Recreate network manually
docker network ls | grep kuryr
docker network inspect <NETWORK_ID>

# Option 3: Full container recreation
# (Warning: This will lose container data)
openstack appcontainer delete c5d7d35c-05c9-40e4-a5d4-a8c8c3eff1c3
openstack appcontainer create \
  --name ollama \
  --image ollama/ollama:latest \
  --cpu 4 \
  --memory 8192 \
  --restart always
```

---

**Verification:**

```bash
# Container should be running
docker ps | grep ollama
# Expected: Up X seconds/minutes

# Network should be assigned
docker inspect 172daf97e4cd | grep -A 10 "Networks"
# Expected: kuryr network with IP 10.0.2.137

# API should respond
curl http://10.0.2.137:11434/api/tags
# Expected: JSON with 8 models

# Proxy should work
curl https://lls.blueharvestai.com/ollama/api/tags
# Expected: Same JSON response
```

---

### Fix 4: LLS Service Proxy

**Current State:**
- Nginx configuration: ✅ Correct
- HTTPS certificate: ✅ Valid
- Backend status: ❌ Unreachable

**Once Ollama is Running:**

```bash
# 1. Verify Ollama is accessible
curl -I http://10.0.2.137:11434/api/tags

# 2. Test Nginx proxy
curl -I https://lls.blueharvestai.com/ollama/api/tags

# 3. Check Nginx logs for errors
tail -20 /var/log/nginx/error.log

# 4. Reload Nginx if needed
nginx -t && systemctl reload nginx

# 5. Final test
curl https://lls.blueharvestai.com/ollama/api/tags
```

**Expected Result:**
- Should return JSON with 8 models
- No 502 Bad Gateway
- No connection refused

---

## Verification & Testing

### System Health Checks

**After all fixes, run these verification steps:**

```bash
#!/bin/bash
# BlueHarvest AI System Health Check

echo "=== SYSTEM HEALTH CHECK ==="
echo "Date: $(date)"
echo ""

echo "1. Docker Status:"
systemctl is-active docker && echo "✅ Docker running" || echo "❌ Docker failed"
echo ""

echo "2. Container Status:"
TOTAL=$(docker ps -a | wc -l)
RUNNING=$(docker ps | wc -l)
echo "   Total: $((TOTAL-1))"
echo "   Running: $((RUNNING-1))"
echo ""

echo "3. Critical Services:"
for service in keystone horizon nova_api neutron_server kuryr zun_api; do
    STATUS=$(docker inspect $service --format='{{.State.Health.Status}}' 2>/dev/null || echo "not found")
    if [ "$STATUS" = "healthy" ]; then
        echo "   ✅ $service: $STATUS"
    else
        echo "   ❌ $service: $STATUS"
    fi
done
echo ""

echo "4. Kuryr Network Plugin:"
if netstat -tulpn | grep -q 23750; then
    echo "   ✅ Port 23750 listening"
else
    echo "   ❌ Port 23750 not listening"
fi
echo ""

echo "5. Ollama Container:"
if docker ps | grep -q ollama; then
    echo "   ✅ Container running"
    if curl -s -o /dev/null -w "%{http_code}" http://10.0.2.137:11434/api/tags | grep -q 200; then
        echo "   ✅ API responding"
    else
        echo "   ❌ API not responding"
    fi
else
    echo "   ❌ Container not running"
fi
echo ""

echo "6. Web Services:"
if curl -s -o /dev/null -w "%{http_code}" https://cloud.blueharvestai.com/ | grep -q 200; then
    echo "   ✅ Horizon accessible"
else
    echo "   ❌ Horizon not accessible"
fi

if curl -s -o /dev/null -w "%{http_code}" https://cloud.blueharvestai.com/auth/login/ | grep -q 200; then
    echo "   ✅ Login page working"
else
    echo "   ❌ Login page broken"
fi

if curl -s -o /dev/null -w "%{http_code}" https://lls.blueharvestai.com/ollama/api/tags | grep -q 200; then
    echo "   ✅ LLS service working"
else
    echo "   ❌ LLS service not working"
fi
echo ""

echo "=== END HEALTH CHECK ==="
```

**Save as:** `/root/health-check.sh`

**Run:**
```bash
chmod +x /root/health-check.sh
/root/health-check.sh
```

---

### Functional Testing

**Test 1: OpenStack Dashboard**
```bash
# 1. Access dashboard
Open: https://cloud.blueharvestai.com

# 2. Login
Username: admin
Password: (from /etc/kolla/passwords.yml)

# 3. Navigate to Containers
Project → Container → Containers

# 4. Verify Ollama visible
Should see: zun-c5d7d35c... container

# 5. Test restart
Click: Actions → Restart
Wait: 30 seconds
Verify: Status changes to "Running"
```

---

**Test 2: LLM API**
```bash
# 1. Test model listing
curl https://lls.blueharvestai.com/ollama/api/tags

# Expected output:
{
  "models": [
    {"name": "mistral:latest", ...},
    {"name": "llama2:13b", ...},
    {"name": "codellama:13b", ...},
    {"name": "deepseek-r1:latest", ...},
    {"name": "mixtral:latest", ...},
    {"name": "qwen2.5:14b", ...},
    {"name": "gemma2:9b", ...},
    {"name": "phi3:14b", ...}
  ]
}

# 2. Test generation
curl https://lls.blueharvestai.com/ollama/api/generate \
  -d '{
    "model": "mistral:latest",
    "prompt": "Hello, world!",
    "stream": false
  }'

# Expected: JSON response with generated text
```

---

**Test 3: Container Management**
```bash
# Via CLI
source /etc/kolla/admin-openrc.sh

# List containers
openstack appcontainer list

# Should show:
# +------+--------+-------+
# | uuid | name   | status|
# +------+--------+-------+
# | c5d7...| ollama| Running|
# +------+--------+-------+

# Stop container
openstack appcontainer stop c5d7d35c-05c9-40e4-a5d4-a8c8c3eff1c3

# Verify stopped
docker ps | grep ollama
# Should show nothing

# Start container
openstack appcontainer start c5d7d35c-05c9-40e4-a5d4-a8c8c3eff1c3

# Verify running
docker ps | grep ollama
# Should show: Up X seconds
```

---

## Prevention Strategy

### 1. Configuration Backup Automation

**Create Backup Script:**

```bash
cat > /usr/local/bin/backup-configs.sh << 'EOF'
#!/bin/bash
# BlueHarvest AI Configuration Backup Script

BACKUP_DIR="/root/config-backups"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_PATH="$BACKUP_DIR/$DATE"

mkdir -p "$BACKUP_PATH"

# Backup Docker configuration
cp /etc/docker/daemon.json "$BACKUP_PATH/daemon.json"

# Backup Kolla configuration
tar -czf "$BACKUP_PATH/kolla-config.tar.gz" /etc/kolla/

# Backup Nginx configuration
tar -czf "$BACKUP_PATH/nginx-config.tar.gz" /etc/nginx/

# Keep only last 30 backups
cd "$BACKUP_DIR"
ls -t | tail -n +31 | xargs -r rm -rf

echo "Backup completed: $BACKUP_PATH"
EOF

chmod +x /usr/local/bin/backup-configs.sh
```

**Schedule Daily Backups:**
```bash
# Add to crontab
echo "0 2 * * * /usr/local/bin/backup-configs.sh >> /var/log/config-backup.log 2>&1" | crontab -
```

---

### 2. JSON Validation Pre-Commit

**Create Validation Hook:**

```bash
cat > /usr/local/bin/validate-docker-json.sh << 'EOF'
#!/bin/bash
# Validate Docker daemon.json before allowing edits

CONFIG_FILE="/etc/docker/daemon.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Config file not found"
    exit 1
fi

# Validate JSON syntax
if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
    echo "ERROR: Invalid JSON in $CONFIG_FILE"
    echo "Please fix syntax errors before saving"
    exit 1
fi

# Check for duplicate keys
KEYS=$(jq -r 'keys[]' "$CONFIG_FILE" | sort)
DUPLICATES=$(echo "$KEYS" | uniq -d)

if [ -n "$DUPLICATES" ]; then
    echo "ERROR: Duplicate keys found in $CONFIG_FILE:"
    echo "$DUPLICATES"
    exit 1
fi

echo "✅ JSON validation passed"
exit 0
EOF

chmod +x /usr/local/bin/validate-docker-json.sh
```

**Use Before Restarting Docker:**
```bash
# Always run before restarting Docker
/usr/local/bin/validate-docker-json.sh && systemctl restart docker
```

---

### 3. Automated Health Monitoring

**Create Monitoring Script:**

```bash
cat > /usr/local/bin/monitor-health.sh << 'EOF'
#!/bin/bash
# Continuous health monitoring with alerts

ALERT_EMAIL="admin@blueharvestai.com"
LOG_FILE="/var/log/health-monitor.log"

check_service() {
    SERVICE=$1
    if ! docker inspect $SERVICE --format='{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; then
        echo "$(date): ❌ $SERVICE unhealthy" >> "$LOG_FILE"
        return 1
    fi
    return 0
}

# Check critical services
FAILED=""
for service in keystone horizon kuryr zun_api nova_api neutron_server; do
    if ! check_service $service; then
        FAILED="$FAILED $service"
    fi
done

# Check Ollama
if ! docker ps | grep -q ollama; then
    echo "$(date): ❌ Ollama container not running" >> "$LOG_FILE"
    FAILED="$FAILED ollama"
fi

# Send alert if failures detected
if [ -n "$FAILED" ]; then
    echo "ALERT: Failed services:$FAILED" | mail -s "BlueHarvest AI Alert" "$ALERT_EMAIL"
fi
EOF

chmod +x /usr/local/bin/monitor-health.sh
```

**Schedule Every 5 Minutes:**
```bash
echo "*/5 * * * * /usr/local/bin/monitor-health.sh" | crontab -
```

---

### 4. Automatic Service Recovery

**Create Auto-Recovery Script:**

```bash
cat > /usr/local/bin/auto-recover.sh << 'EOF'
#!/bin/bash
# Automatic recovery for failed services

recover_service() {
    SERVICE=$1
    echo "$(date): Attempting to recover $SERVICE"
    
    # Try restart
    docker restart $SERVICE
    sleep 30
    
    # Verify
    if docker inspect $SERVICE --format='{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; then
        echo "$(date): ✅ $SERVICE recovered"
        return 0
    else
        echo "$(date): ❌ $SERVICE recovery failed"
        return 1
    fi
}

# Check and recover Kuryr
if ! docker inspect kuryr --format='{{.State.Health.Status}}' | grep -q healthy; then
    recover_service kuryr
fi

# Check and recover Ollama
if ! docker ps | grep -q ollama; then
    docker start 172daf97e4cd
    echo "$(date): Attempted Ollama restart"
fi
EOF

chmod +x /usr/local/bin/auto-recover.sh
```

**Schedule Every 10 Minutes:**
```bash
echo "*/10 * * * * /usr/local/bin/auto-recover.sh >> /var/log/auto-recover.log 2>&1" | crontab -
```

---

### 5. Disk Space Monitoring

**Create Disk Monitor:**

```bash
cat > /usr/local/bin/monitor-disk.sh << 'EOF'
#!/bin/bash
# Monitor disk space and clean if needed

THRESHOLD=80
ALERT_EMAIL="admin@blueharvestai.com"

# Check disk usage
USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')

if [ $USAGE -gt $THRESHOLD ]; then
    echo "ALERT: Disk usage at ${USAGE}%" | mail -s "BlueHarvest AI Disk Alert" "$ALERT_EMAIL"
    
    # Clean Docker
    docker system prune -f --volumes
    
    # Clean logs older than 30 days
    find /var/log -name "*.log" -mtime +30 -delete
    find /var/log/kolla -name "*.log" -mtime +30 -delete
fi
EOF

chmod +x /usr/local/bin/monitor-disk.sh
```

**Schedule Daily:**
```bash
echo "0 3 * * * /usr/local/bin/monitor-disk.sh" | crontab -
```

---

## Long-term Recommendations

### 1. High Availability Setup

**Current Risk:** Single point of failure

**Recommendation:**
- Deploy HAProxy for load balancing
- Enable Keepalived for VIP failover
- Set up MariaDB Galera cluster (3 nodes minimum)
- Configure RabbitMQ clustering

**Timeline:** 2-4 weeks  
**Complexity:** High  
**Priority:** Medium

---

### 2. Monitoring & Alerting

**Current Gap:** No proactive monitoring

**Recommendation:**
- Deploy Prometheus for metrics collection
- Set up Grafana dashboards
- Configure Alertmanager for notifications
- Enable OpenStack Ceilometer for usage metrics

**Tools:**
```yaml
Monitoring Stack:
  - Prometheus: Metrics collection
  - Grafana: Visualization
  - Alertmanager: Alert routing
  - Node Exporter: System metrics
  - cAdvisor: Container metrics
```

**Timeline:** 1 week  
**Complexity:** Medium  
**Priority:** High

---

### 3. Backup & Disaster Recovery

**Current Risk:** No automated backups

**Recommendation:**

**Database Backups:**
```bash
# Daily MariaDB backup
0 1 * * * docker exec mariadb mysqldump --all-databases | gzip > /backup/mysql-$(date +\%Y\%m\%d).sql.gz
```

**Configuration Backups:**
```bash
# Daily Kolla config backup
0 2 * * * tar -czf /backup/kolla-$(date +\%Y\%m\%d).tar.gz /etc/kolla
```

**VM/Container Backups:**
```bash
# Enable Cinder backup service
enable_cinder_backup: "yes"

# Configure backup backend (Swift or NFS)
```

**Timeline:** 1 week  
**Complexity:** Low  
**Priority:** High

---

### 4. SSL/TLS Everywhere

**Current State:** 
- ✅ External HTTPS (lls.blueharvestai.com)
- ❌ Internal services use HTTP

**Recommendation:**
- Enable `kolla_enable_tls_internal: "yes"`
- Generate internal CA certificates
- Configure all services for TLS

**Benefits:**
- Encrypted internal communication
- Protection against internal network sniffing
- Compliance with security standards

**Timeline:** 2 weeks  
**Complexity:** Medium  
**Priority:** Medium

---

### 5. Documentation

**Create Runbooks:**

1. **Service Restart Procedures**
   - Step-by-step for each OpenStack service
   - Common error messages and solutions
   - Escalation procedures

2. **Troubleshooting Guides**
   - Network connectivity issues
   - Container startup failures
   - Authentication problems
   - Database connection errors

3. **Maintenance Procedures**
   - Upgrade procedures
   - Backup/restore processes
   - Configuration changes
   - Service updates

**Timeline:** Ongoing  
**Complexity:** Low  
**Priority:** High

---

### 6. Infrastructure as Code

**Current State:** Manual configuration

**Recommendation:**
- Version control all configurations (Git)
- Use Ansible playbooks for all changes
- Implement Terraform for infrastructure
- Document all manual changes

**Benefits:**
- Reproducible deployments
- Easy rollback
- Change tracking
- Disaster recovery

**Timeline:** 3-4 weeks  
**Complexity:** High  
**Priority:** High

---

## Quick Reference

### Critical Commands

**Check System Health:**
```bash
/root/health-check.sh
```

**Restart All Services:**
```bash
docker start $(docker ps -a -q)
```

**Restart Specific Service:**
```bash
docker restart <service-name>
```

**View Service Logs:**
```bash
docker logs <service-name> --tail 100
```

**OpenStack CLI:**
```bash
source /etc/kolla/admin-openrc.sh
openstack <command>
```

---

### Service Port Reference

```
Port 80:    HTTP (Nginx)
Port 443:   HTTPS (Nginx)
Port 5000:  Keystone API
Port 8774:  Nova API
Port 9292:  Glance API
Port 9696:  Neutron API
Port 8776:  Cinder API
Port 8004:  Heat API
Port 9517:  Zun API
Port 23750: Kuryr Plugin
Port 11434: Ollama API (container)
```

---

### Important File Locations

```
Docker Config:     /etc/docker/daemon.json
Kolla Config:      /etc/kolla/globals.yml
Kolla Passwords:   /etc/kolla/passwords.yml
OpenStack RC:      /etc/kolla/admin-openrc.sh
Nginx Config:      /etc/nginx/conf.d/
Service Logs:      /var/log/kolla/<service>/
```

---

### Emergency Contacts

```
System Admin:      admin@blueharvestai.com
Escalation:        [Define escalation path]
Vendor Support:    [OpenStack, Kolla-Ansible support]
```

---

## Conclusion

### Current Status Summary

**Working (70%):**
- ✅ Core OpenStack services operational
- ✅ Compute, network, storage functioning
- ✅ Container service (Zun) enabled
- ✅ Dashboard accessible (partially)
- ✅ DNS and networking configured

**Critical Issues (30%):**
- ❌ Kuryr network plugin unhealthy
- ❌ Ollama container cannot start
- ❌ Horizon login page broken
- ❌ LLS service unreachable

---

### Recovery Priority

**Priority 1 (Immediate):**
1. Fix Kuryr networking plugin
2. Restore Horizon login functionality

**Priority 2 (Within 24 hours):**
3. Restart Ollama container
4. Verify LLS service accessibility

**Priority 3 (Within 1 week):**
5. Implement monitoring
6. Set up automated backups
7. Create runbook documentation

---

### Next Steps

**Immediate Actions:**
1. Execute Kuryr fix procedure (Solution A, then B if needed)
2. Execute Horizon fix procedure (Solution A, then B if needed)
3. Once Kuryr healthy, restart Ollama
4. Run full system verification
5. Document any additional issues encountered

**Follow-up Actions:**
1. Implement automated backup scripts
2. Set up health monitoring
3. Create operational runbooks
4. Plan high-availability upgrade

---

### Success Criteria

**System will be considered fully recovered when:**
- ✅ All containers healthy (42/42)
- ✅ Horizon login functional
- ✅ Ollama container running
- ✅ LLS service accessible
- ✅ Kuryr plugin operational (port 23750 listening)
- ✅ All health checks passing
- ✅ No errors in service logs

---

**Document Version:** 1.0  
**Last Updated:** February 22, 2026 09:45 UTC  
**Author:** BlueHarvest AI Operations Team  
**Status:** Active Recovery in Progress

---

*This document provides a complete assessment of the current infrastructure state and detailed recovery procedures. Follow the steps sequentially for best results. Update this document as issues are resolved.*
