

**Priority:** HIGH

**Requirement:** Define and enforce backup retention policies based on compliance requirements.

**OpenStack Implementation:**
```bash
# Set backup retention in days
openstack volume backup create volume-id \
  --name daily-backup \
  --property retention_days=90

# Automated retention enforcement
#!/usr/bin/env python3
# cleanup_old_backups.py
import openstack
from datetime import datetime, timedelta

conn = openstack.connect(cloud='production')
retention_days = 90

for backup in conn.block_storage.backups():
    created = datetime.fromisoformat(backup.created_at)
    age = datetime.now() - created
    
    if age > timedelta(days=retention_days):
        print(f"Deleting backup {backup.name} (age: {age.days} days)")
        conn.block_storage.delete_backup(backup.id)
```

**Compliance-Based Retention:**
- **PCI DSS:** 3 months minimum for cardholder data
- **GDPR:** As long as necessary for purpose
- **SOX:** 7 years for financial records
- **HIPAA:** 6 years minimum

---

### 7.3 Implement Automated Threat Response

**Priority:** MEDIUM

**Requirement:** Automate response to common security events.

**OpenStack Implementation:**

**Wazuh Active Response:**
```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <active-response>
    <command>isolate-instance</command>
    <location>local</location>
    <rules_id>100010</rules_id>
    <timeout>3600</timeout>
  </active-response>
  
  <active-response>
    <command>block-ip</command>
    <location>server</location>
    <rules_id>100020</rules_id>
    <timeout>600</timeout>
  </active-response>
</ossec_config>

<!-- Custom commands -->
<command>
  <name>isolate-instance</name>
  <executable>isolate-instance.sh</executable>
  <expect>srcip,user</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

**SOAR Integration:**
```python
#!/usr/bin/env python3
# soar_integration.py - Integrate with TheHive/Cortex

from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

api = TheHiveApi('http://thehive:9000', 'api-key')

def create_incident(event_data):
    """Create incident in TheHive from security event"""
    
    artifacts = [
        AlertArtifact(dataType='ip', data=event_data['source_ip']),
        AlertArtifact(dataType='other', data=event_data['instance_id'])
    ]
    
    alert = Alert(
        title=f"OpenStack Security Event: {event_data['type']}",
        tlp=2,
        severity=2,
        description=event_data['description'],
        type='openstack-security',
        source='openstack-monitoring',
        artifacts=artifacts
    )
    
    response = api.create_alert(alert)
    return response.id

# Example: Auto-create incident from Elasticsearch alert
from elasticsearch import Elasticsearch
es = Elasticsearch(['http://elasticsearch:9200'])

# Watch for critical security events
def monitor_security_events():
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"level": "critical"}},
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        }
    }
    
    results = es.search(index="openstack-security-*", body=query)
    
    for hit in results['hits']['hits']:
        event = hit['_source']
        incident_id = create_incident(event)
        print(f"Created incident {incident_id} for event {hit['_id']}")
```

---

## 8. Compliance and Governance

### 8.1 Implement Policy-as-Code

**Priority:** HIGH

**Requirement:** Define and enforce security policies programmatically.

**OpenStack Implementation:**

**Open Policy Agent (OPA) Integration:**
```rego
# policy.rego - Security policies for OpenStack
package openstack.security

# Deny instance creation without encryption
deny[msg] {
    input.action == "create_instance"
    not input.volume_encrypted
    msg := "Instances must use encrypted volumes"
}

# Deny public IP assignment to restricted networks
deny[msg] {
    input.action == "assign_floating_ip"
    input.network_classification == "restricted"
    msg := "Cannot assign public IPs to restricted network resources"
}

# Require MFA for privileged operations
deny[msg] {
    input.action in ["delete_instance", "modify_security_group"]
    not input.user_mfa_verified
    msg := "MFA required for privileged operations"
}

# Enforce tagging requirements
deny[msg] {
    input.action == "create_resource"
    not input.tags.owner
    not input.tags.classification
    msg := "Resources must be tagged with owner and classification"
}

# Restrict instance creation to approved images
deny[msg] {
    input.action == "create_instance"
    not approved_image(input.image_id)
    msg := sprintf("Image %v is not approved for use", [input.image_id])
}

approved_image(image_id) {
    approved_images := ["ubuntu-hardened", "rhel-8-cis", "debian-secure"]
    image_id in approved_images
}
```

**Policy Enforcement Middleware:**
```python
#!/usr/bin/env python3
# opa_middleware.py - OPA enforcement for OpenStack APIs

from opa_client import OpaClient
from oslo_policy import policy as oslo_policy

class OPAEnforcementMiddleware:
    def __init__(self, app):
        self.app = app
        self.opa_client = OpaClient(host='opa-server', port=8181)
    
    def __call__(self, environ, start_response):
        # Extract request context
        context = {
            'action': environ.get('HTTP_X_ACTION'),
            'user_id': environ.get('HTTP_X_USER_ID'),
            'project_id': environ.get('HTTP_X_PROJECT_ID'),
            'user_mfa_verified': environ.get('HTTP_X_MFA_VERIFIED') == 'true',
            'volume_encrypted': environ.get('HTTP_X_VOLUME_ENCRYPTED') == 'true',
        }
        
        # Query OPA for policy decision
        result = self.opa_client.check_permission(
            input_data=context,
            policy_name='openstack/security'
        )
        
        if not result['allow']:
            # Policy violation - return 403
            start_response('403 Forbidden', [
                ('Content-Type', 'application/json')
            ])
            return [json.dumps({
                'error': 'Policy violation',
                'violations': result['deny']
            }).encode()]
        
        # Allow request to proceed
        return self.app(environ, start_response)
```

---

### 8.2 Conduct Regular Security Assessments

**Priority:** HIGH

**Requirement:** Perform vulnerability assessments and penetration testing.

**OpenStack Implementation:**

**Automated Vulnerability Scanning:**
```bash
# OpenVAS scanning of OpenStack infrastructure
openvas-start

# Create scan task for OpenStack controllers
omp -u admin -w admin \
  --xml='<create_task>
    <name>OpenStack Controllers Scan</name>
    <target id="controller-target-id"/>
    <config id="full-and-fast-config-id"/>
    <scanner id="openvas-scanner-id"/>
    <schedule>
      <icalendar>FREQ=WEEKLY;BYDAY=SU</icalendar>
    </schedule>
  </create_task>'

# Automated remediation tracking
omp -u admin -w admin -G > scan-results.xml
python3 parse-vulnerabilities.py scan-results.xml > remediation-plan.json
```

**OpenSCAP Compliance Scanning:**
```bash
# Scan OpenStack nodes against CIS benchmarks
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_server_l2 \
  --results scan-results.xml \
  --report scan-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml

# Generate remediation script
oscap xccdf generate fix \
  --profile xccdf_org.ssgproject.content_profile_cis_server_l2 \
  --output remediation.sh \
  scan-results.xml

# Apply remediations
bash remediation.sh
```

**Penetration Testing Checklist:**
- [ ] API authentication and authorization bypass
- [ ] Metadata service exploitation
- [ ] Instance escape attempts
- [ ] Network segmentation validation
- [ ] Privilege escalation testing
- [ ] Encryption verification
- [ ] Supply chain security (images, packages)
- [ ] DoS/DDoS resilience

**Schedule:**
- **Vulnerability scans:** Weekly automated
- **Compliance scans:** Monthly
- **Internal penetration testing:** Quarterly
- **External penetration testing:** Annually
- **Red team exercises:** Bi-annually

---

### 8.3 Maintain Security Baselines

**Priority:** HIGH

**Requirement:** Define and enforce security configuration baselines.

**OpenStack Implementation:**

**Ansible Security Baselines:**
```yaml
# playbooks/openstack-security-baseline.yml
---
- name: Apply OpenStack Security Baseline
  hosts: openstack_all
  become: yes
  
  tasks:
    - name: Ensure SELinux is enforcing
      selinux:
        policy: targeted
        state: enforcing
    
    - name: Configure firewalld
      firewalld:
        service: "{{ item }}"
        permanent: yes
        state: enabled
      loop:
        - ssh
        - https
    
    - name: Harden SSH configuration
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - { regexp: '^PermitRootLogin', line: 'PermitRootLogin no' }
        - { regexp: '^PasswordAuthentication', line: 'PasswordAuthentication no' }
        - { regexp: '^X11Forwarding', line: 'X11Forwarding no' }
      notify: restart sshd
    
    - name: Configure auditd for OpenStack
      copy:
        src: files/openstack-audit.rules
        dest: /etc/audit/rules.d/openstack.rules
      notify: restart auditd
    
    - name: Set password policies
      lineinfile:
        path: /etc/login.defs
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - { regexp: '^PASS_MAX_DAYS', line: 'PASS_MAX_DAYS 90' }
        - { regexp: '^PASS_MIN_DAYS', line: 'PASS_MIN_DAYS 1' }
        - { regexp: '^PASS_MIN_LEN', line: 'PASS_MIN_LEN 14' }
    
    - name: Install and configure AIDE
      package:
        name: aide
        state: present
    
    - name: Initialize AIDE database
      command: aide --init
      args:
        creates: /var/lib/aide/aide.db.new.gz
    
    - name: Schedule daily AIDE checks
      cron:
        name: "AIDE integrity check"
        hour: "2"
        minute: "0"
        job: "/usr/sbin/aide --check | mail -s 'AIDE Report' security@example.com"
  
  handlers:
    - name: restart sshd
      service:
        name: sshd
        state: restarted
    
    - name: restart auditd
      service:
        name: auditd
        state: restarted
```

**Configuration Drift Detection:**
```python
#!/usr/bin/env python3
# detect_drift.py - Monitor configuration drift

import openstack
import json
from deepdiff import DeepDiff

# Define baseline configuration
BASELINE = {
    'security_groups': {
        'default': {
            'rules': [
                {'direction': 'egress', 'ethertype': 'IPv4'},
                {'direction': 'egress', 'ethertype': 'IPv6'}
            ]
        }
    },
    'volume_types': {
        'encrypted': {
            'encryption': {
                'provider': 'luks',
                'cipher': 'aes-xts-plain64',
                'key_size': 256
            }
        }
    }
}

def check_configuration_drift():
    conn = openstack.connect(cloud='production')
    
    # Get current configuration
    current = {
        'security_groups': {},
        'volume_types': {}
    }
    
    for sg in conn.network.security_groups():
        current['security_groups'][sg.name] = {
            'rules': [dict(r) for r in sg.security_group_rules]
        }
    
    for vt in conn.block_storage.types():
        encryption = conn.block_storage.get_type_encryption(vt.id)
        current['volume_types'][vt.name] = {
            'encryption': dict(encryption) if encryption else None
        }
    
    # Compare with baseline
    diff = DeepDiff(BASELINE, current, ignore_order=True)
    
    if diff:
        print("⚠️  Configuration drift detected!")
        print(json.dumps(diff, indent=2))
        return False
    else:
        print("✓ Configuration matches baseline")
        return True

if __name__ == '__main__':
    check_configuration_drift()
```

---

### 8.4 Document Security Controls

**Priority:** MEDIUM

**Requirement:** Maintain comprehensive security documentation.

**Required Documentation:**
1. **System Security Plan (SSP)**
   - Architecture diagrams
   - Data flow diagrams
   - Security control implementation
   - Risk assessment

2. **Security Operations Procedures**
   - Incident response playbooks
   - Backup and recovery procedures
   - Access management processes
   - Change management procedures

3. **Configuration Standards**
   - Hardening guides
   - Baseline configurations
   - Approved software lists
   - Network architecture standards

4. **Compliance Documentation**
   - Policy documents
   - Control matrices
   - Audit reports
   - Risk registers

**Documentation-as-Code:**
```yaml
# docs/security-controls.yml
controls:
  - id: SC-1
    family: System and Communications Protection
    title: Network Segmentation
    implementation:
      description: "Implement network segmentation using Neutron networks and security groups"
      responsible: Network Team
      status: implemented
      evidence:
        - type: configuration
          location: neutron/network-config.yml
        - type: diagram
          location: docs/network-architecture.pdf
    testing:
      frequency: quarterly
      last_test: 2025-10-01
      result: passed
```

---

## 9. API Security

### 9.1 Implement API Rate Limiting

**Priority:** HIGH

**Requirement:** Protect APIs from abuse and DDoS attacks.

**OpenStack Implementation:**

**oslo.middleware Rate Limiting:**
```python
# In paste.ini for all services
[filter:ratelimit]
paste.filter_factory = oslo_middleware.rate_limit:RateLimitFilter.factory
rate_limit_burst = 10
rate_limit_interval = 1
rate_limit_except = 127.0.0.1,10.0.0.0/8

[pipeline:main]
pipeline = ratelimit authtoken keystonecontext ... app
```

**Custom Rate Limiter:**
```python
#!/usr/bin/env python3
# api_rate_limiter.py

from functools import wraps
from flask import request, jsonify
import redis
from datetime import datetime, timedelta

redis_client = redis.Redis(host='redis', port=6379, db=0)

def rate_limit(calls=100, period=60):
    """Rate limit decorator"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Use user ID or IP as key
            user_id = request.headers.get('X-User-ID', request.remote_addr)
            key = f"ratelimit:{func.__name__}:{user_id}"
            
            # Get current count
            current = redis_client.get(key)
            
            if current and int(current) >= calls:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': redis_client.ttl(key)
                }), 429
            
            # Increment counter
            pipe = redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, period)
            pipe.execute()
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Usage in API endpoint
@app.route('/api/servers', methods=['POST'])
@rate_limit(calls=10, period=60)
def create_server():
    # Server creation logic
    pass
```

**HAProxy Rate Limiting:**
```haproxy
# /etc/haproxy/haproxy.cfg
frontend openstack_api
    bind *:443 ssl crt /etc/ssl/certs/openstack.pem
    
    # Rate limiting with stick tables
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request deny if { sc_http_req_rate(0) gt 100 }
    
    # Connection rate limiting
    acl too_fast sc0_conn_rate gt 50
    http-request deny if too_fast
    
    default_backend openstack_api_servers
```

---

### 9.2 Enable API Request Validation

**Priority:** HIGH

**Requirement:** Validate all API inputs to prevent injection attacks.

**OpenStack Implementation:**

**JSON Schema Validation:**
```python
# nova/api/validation.py
from jsonschema import validate, ValidationError

CREATE_SERVER_SCHEMA = {
    "type": "object",
    "properties": {
        "server": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                    "pattern": "^[a-zA-Z0-9-_]+$"
                },
                "imageRef": {
                    "type": "string",
                    "format": "uuid"
                },
                "flavorRef": {
                    "type": "string"
                }
            },
            "required": ["name", "flavorRef"],
            "additionalProperties": False
        }
    },
    "required": ["server"],
    "additionalProperties": False
}

def validate_create_server(body):
    try:
        validate(instance=body, schema=CREATE_SERVER_SCHEMA)
    except ValidationError as e:
        raise webob.exc.HTTPBadRequest(
            explanation=f"Invalid request: {e.message}"
        )
```

**Input Sanitization:**
```python
import bleach
import re

def sanitize_input(data):
    """Sanitize user input"""
    if isinstance(data, str):
        # Remove HTML tags
        data = bleach.clean(data, tags=[], strip=True)
        
        # Remove SQL injection patterns
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)",
            r"(--|\;|\/\*|\*\/)",
            r"(\bOR\b.*\=.*\=)",
            r"(\bUNION\b.*\bSELECT\b)"
        ]
        for pattern in sql_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                raise ValueError("Potential SQL injection detected")
        
        # Remove XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
        ]
        for pattern in xss_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                raise ValueError("Potential XSS detected")
    
    elif isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    
    return data
```

---

### 9.3 Implement API Authentication and Authorization

**Priority:** CRITICAL

**Requirement:** Enforce strong authentication and fine-grained authorization for APIs.

**OpenStack Implementation:**

**OAuth 2.0 with Keystone:**
```python
# keystone.conf
[oauth1]
driver = sql

# Create OAuth consumer
openstack registered consumer create \
  --description "Mobile App" \
  mobile-app-consumer

# User authorizes consumer
openstack registered consumer authorize \
  <consumer-id> \
  --request-key <request-key> \
  --request-secret <request-secret> \
  --role member \
  --project <project-id>
```

**API Key Management:**
```bash
# Application credentials (preferred over passwords)
openstack application credential create api-service \
  --secret supersecret \
  --role member \
  --expiration "2026-01-01T00:00:00" \
  --unrestricted

# Restrict to specific services
openstack application credential create readonly-api \
  --secret anothersecret \
  --role reader \
  --access-rules '[{
    "path": "/v2.1/servers",
    "method": "GET",
    "service": "compute"
  }]'
```

**JWT Token Validation:**
```python
import jwt
from functools

## 6. Logging and Monitoring

### 6.1 Enable Centralized Logging

**Priority:** CRITICAL

**Requirement:** Aggregate all OpenStack service logs centrally for analysis.

**OpenStack Implementation:**

**ELK Stack Deployment:**
```yaml
# docker-compose.yml for ELK
version: '3'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
    volumes:
      - esdata:/usr/share/elasticsearch/data
  
  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
  
  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
```

**Logstash Pipeline for OpenStack:**
```ruby
# /etc/logstash/pipeline/openstack.conf
input {
  tcp {
    port => 5000
    type => "openstack-logs"
  }
}

filter {
  if [type] == "openstack-logs" {
    grok {
      match => { 
        "message" => "%{TIMESTAMP_ISO8601:timestamp} %{NUMBER:pid} %{LOGLEVEL:level} %{NOTSPACE:component} \[%{NOTSPACE:request_id}\] %{GREEDYDATA:message}"
      }
    }
    
    date {
      match => [ "timestamp", "ISO8601" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "openstack-%{+YYYY.MM.dd}"
  }
}
```

**Configure Services to Send Logs:**
```ini
# In nova.conf, neutron.conf, etc.
[DEFAULT]
log_file = /var/log/nova/nova.log
debug = False
verbose = True

[oslo_log]
use_syslog = True
syslog_log_facility = LOG_LOCAL0
```

---

### 6.2 Implement Security Monitoring and Alerting

**Priority:** CRITICAL

**Requirement:** Monitor for security events and alert on suspicious activity.

**OpenStack Implementation:**

**Wazuh SIEM Configuration:**
```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <syslog_output>
    <server>siem.example.com</server>
    <port>514</port>
    <format>json</format>
  </syslog_output>
  
  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>10</email_alert_level>
  </alerts>
  
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>
  </global>
</ossec_config>
```

**Critical Alerts:**
1. Failed authentication attempts (>5 in 5 min)
2. Privileged command execution
3. Resource quota violations
4. Unauthorized API access
5. Security group changes
6. Instance creation/deletion outside business hours
7. Encryption key access
8. Network policy violations

**Prometheus Alerting Rules:**
```yaml
# /etc/prometheus/alerts/openstack.yml
groups:
  - name: openstack_security
    interval: 30s
    rules:
      - alert: HighFailedAuthRate
        expr: rate(keystone_auth_failed_total[5m]) > 10
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High authentication failure rate"
          description: "{{ $value }} failed auth attempts per second"
      
      - alert: UnauthorizedInstanceCreation
        expr: increase(nova_instance_created_total{authorized="false"}[1h]) > 0
        labels:
          severity: high
        annotations:
          summary: "Unauthorized instance creation detected"
      
      - alert: SecurityGroupModified
        expr: changes(neutron_security_group_rules_total[5m]) > 0
        labels:
          severity: medium
        annotations:
          summary: "Security group rules modified"
```

**Grafana Dashboard:**
```json
{
  "dashboard": {
    "title": "OpenStack Security Monitoring",
    "panels": [
      {
        "title": "Failed Authentication Attempts",
        "targets": [{
          "expr": "rate(keystone_auth_failed_total[5m])"
        }]
      },
      {
        "title": "API Request Rate by User",
        "targets": [{
          "expr": "sum by (user) (rate(openstack_api_requests_total[5m]))"
        }]
      }
    ]
  }
}
```

---

### 6.3 Configure Log Retention

**Priority:** HIGH

**Requirement:** Retain logs according to compliance requirements in immutable storage.

**OpenStack Implementation:**
```yaml
# Elasticsearch ILM policy
PUT _ilm/policy/openstack-logs-policy
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "50GB",
            "max_age": "7d"
          }
        }
      },
      "warm": {
        "min_age": "30d",
        "actions": {
          "shrink": {
            "number_of_shards": 1
          },
          "forcemerge": {
            "max_num_segments": 1
          }
        }
      },
      "cold": {
        "min_age": "90d",
        "actions": {
          "freeze": {},
          "allocate": {
            "require": {
              "data": "cold"
            }
          }
        }
      },
      "delete": {
        "min_age": "365d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

**Log Retention Periods:**
- **Security logs:** 1 year minimum (2+ years recommended)
- **Audit logs:** 7 years for compliance
- **Access logs:** 90 days minimum
- **Debug logs:** 30 days
- **Application logs:** 90 days

---

### 6.4 Implement User Activity Monitoring

**Priority:** MEDIUM

**Requirement:** Track user actions for anomaly detection and forensics.

**OpenStack Implementation:**
```python
#!/usr/bin/env python3
# user_activity_monitor.py
import openstack
from collections import defaultdict
from datetime import datetime, timedelta

conn = openstack.connect(cloud='production')

# Query audit logs via ELK
from elasticsearch import Elasticsearch
es = Elasticsearch(['http://elasticsearch:9200'])

def analyze_user_behavior(user_id, days=7):
    """Detect anomalous user behavior"""
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"initiator.id": user_id}},
                    {"range": {"@timestamp": {"gte": f"now-{days}d"}}}
                ]
            }
        },
        "aggs": {
            "actions": {
                "terms": {"field": "action"}
            },
            "hours": {
                "date_histogram": {
                    "field": "@timestamp",
                    "interval": "hour"
                }
            }
        }
    }
    
    result = es.search(index="openstack-audit-*", body=query)
    
    # Analyze patterns
    actions = result['aggregations']['actions']['buckets']
    hourly = result['aggregations']['hours']['buckets']
    
    # Detect anomalies
    anomalies = []
    
    # Check for off-hours activity
    for bucket in hourly:
        hour = datetime.fromisoformat(bucket['key_as_string']).hour
        if (hour < 6 or hour > 22) and bucket['doc_count'] > 10:
            anomalies.append({
                "type": "off_hours_activity",
                "timestamp": bucket['key_as_string'],
                "count": bucket['doc_count']
            })
    
    # Check for unusual action patterns
    normal_actions = ['read', 'list', 'show']
    risky_actions = ['delete', 'update', 'create']
    
    risky_count = sum(b['doc_count'] for b in actions 
                      if b['key'] in risky_actions)
    
    if risky_count > 50:
        anomalies.append({
            "type": "high_risk_actions",
            "count": risky_count
        })
    
    return anomalies

# Monitor all users
for user in conn.identity.users():
    anomalies = analyze_user_behavior(user.id)
    if anomalies:
        print(f"ALERT: Anomalous behavior detected for {user.name}")
        for anomaly in anomalies:
            print(f"  - {anomaly}")
```

---

## 7. Incident Response

### 7.1 Establish Incident Response Plan

**Priority:** CRITICAL

**Requirement:** Document and test incident response procedures.

**OpenStack-Specific Incidents:**
1. Compromised instances
2. API credential theft
3. Unauthorized access to metadata service
4. Ransomware on storage
5. Network intrusion
6. DDoS attacks on API endpoints
7. Insider threats
8. Supply chain attacks on images

**Response Playbook:**
```yaml
# incident_response.yml
incident_types:
  compromised_instance:
    detection:
      - HIDS alerts
      - Unusual network traffic
      - Suspicious process activity
    
    containment:
      - isolate_instance:
          command: |
            openstack server set <instance-id> \
              --property quarantine=true
            openstack server remove security group <instance-id> default
            openstack security group create quarantine-sg --description "Isolated"
            openstack server add security group <instance-id> quarantine-sg
      
      - snapshot_for_forensics:
          command: |
            openstack server image create <instance-id> \
              --name forensic-snapshot-$(date +%Y%m%d-%H%M%S)
    
    eradication:
      - Rebuild instance from clean image
      - Rotate all credentials
      - Review and patch vulnerabilities
    
    recovery:
      - Restore from clean backup
      - Verify integrity
      - Gradual return to service
    
    lessons_learned:
      - Root cause analysis
      - Update detection rules
      - Improve hardening procedures
```

**Automation Script:**
```python
#!/usr/bin/env python3
# isolate_instance.py
import openstack
import sys

def isolate_instance(instance_id):
    """Isolate compromised instance"""
    conn = openstack.connect(cloud='production')
    
    # Create forensic snapshot
    print(f"Creating forensic snapshot of {instance_id}")
    image = conn.compute.create_server_image(
        instance_id,
        name=f'forensic-{instance_id}-{datetime.now().isoformat()}',
        metadata={'incident': 'security', 'quarantined': 'true'}
    )
    
    # Remove from all security groups
    instance = conn.compute.get_server(instance_id)
    for sg in instance.security_groups:
        conn.compute.remove_security_group_from_server(
            instance_id, sg['name']
        )
    
    # Add to quarantine security group (no ingress/egress)
    conn.compute.add_security_group_to_server(
        instance_id, 'quarantine-sg'
    )
    
    # Set metadata
    conn.compute.set_server_metadata(
        instance_id,
        quarantined='true',
        incident_timestamp=datetime.now().isoformat()
    )
    
    print(f"Instance {instance_id} has been isolated")
    print(f"Forensic snapshot: {image.id}")

if __name__ == '__main__':
    isolate_instance(sys.argv[1])
```

---

### 7.2 Enable Forensic Capabilities

**Priority:** HIGH

**Requirement:** Maintain ability to conduct forensic investigations.

**OpenStack Implementation:**
```bash
# Preserve evidence
openstack server image create compromised-instance \
  --name forensic-evidence-case-12345 \
  --property case_id=12345 \
  --property timestamp=$(date -Is) \
  --property investigator=security-team

# Create volume snapshot
openstack volume snapshot create volume-id \
  --name forensic-snapshot \
  --property case_id=12345 \
  --force

# Export logs
elasticdump \
  --input=http://elasticsearch:9200/openstack-audit-2025.10.10 \
  --output=forensic-logs-case-12345.json \
  --type=data
```

**Memory Forensics:**
```bash
# Suspend instance to preserve memory
openstack server suspend <instance-id>

# Extract memory dump (requires libvirt access)
virsh dumpxml <instance-id> > instance-config.xml
virsh dump <domain> memory-dump.raw --memory-only

# Analyze with Volatility
volatility -f memory-dump.raw --profile=LinuxUbuntu2004x64 linux_pslist
```

---# OpenStack Foundational Security Best Practices

## Executive Summary

This document establishes foundational security best practices for OpenStack deployments, analogous to AWS Foundational Security Best Practices. These controls provide defense-in-depth across identity, network, compute, storage, monitoring, and compliance domains using open-source tools and native OpenStack capabilities.

---

## Table of Contents

1. [Identity and Access Management](#1-identity-and-access-management)
2. [Network Security](#2-network-security)
3. [Compute Security](#3-compute-security)
4. [Storage Security](#4-storage-security)
5. [Data Protection](#5-data-protection)
6. [Logging and Monitoring](#6-logging-and-monitoring)
7. [Incident Response](#7-incident-response)
8. [Compliance and Governance](#8-compliance-and-governance)
9. [API Security](#9-api-security)
10. [Container and Orchestration Security](#10-container-and-orchestration-security)

---

## 1. Identity and Access Management

### 1.1 Enable Multi-Factor Authentication (MFA)

**Priority:** CRITICAL

**Requirement:** Enforce MFA for all privileged accounts and remote access.

**OpenStack Implementation:**
```bash
# Configure Keystone for TOTP MFA
# In keystone.conf
[auth]
methods = password,token,totp

[totp]
enabled = true

# Create MFA user
openstack user create alice --password secret --enable-mfa
```

**Recommended Tools:**
- **privacyIDEA:** Enterprise MFA solution
- **Google Authenticator PAM:** Time-based OTP
- **FreeOTP:** Open-source authenticator app
- **YubiKey:** Hardware token support via PAM

**Validation:**
```bash
# Verify MFA is enabled
openstack user show alice -c name -c options
# Should show: "options": {"multi_factor_auth_enabled": true}
```

---

### 1.2 Implement Role-Based Access Control (RBAC)

**Priority:** HIGH

**Requirement:** Apply principle of least privilege using granular roles.

**OpenStack Implementation:**
```yaml
# Custom policy.yaml for Nova
"os_compute_api:servers:create": "role:instance_creator"
"os_compute_api:servers:delete": "role:instance_admin"
"os_compute_api:servers:start": "role:instance_operator"
"os_compute_api:os-admin-actions": "role:admin"

# Policy for read-only users
"os_compute_api:servers:index": "role:viewer"
"os_compute_api:servers:show": "role:viewer"
```

**Role Hierarchy:**
```bash
# Create custom roles
openstack role create instance_creator
openstack role create instance_operator
openstack role create security_auditor
openstack role create network_admin

# Assign role to user in project
openstack role add --user alice --project prod instance_operator
```

**Best Practices:**
- Separate admin roles by service (compute-admin, network-admin, storage-admin)
- Use project-scoped roles, not domain-wide when possible
- Regular access reviews (quarterly minimum)
- Document role definitions and assignments

---

### 1.3 Rotate Credentials Regularly

**Priority:** HIGH

**Requirement:** Implement automated credential rotation for service accounts and application credentials.

**OpenStack Implementation:**
```bash
# Application credentials with expiration
openstack application credential create api-key \
  --expiration "2026-01-01T00:00:00" \
  --description "Q4 2025 API access"

# Barbican secret rotation
openstack secret store --name db-password-v2 \
  --payload "newsecret" \
  --secret-type passphrase

# Update secret reference
openstack secret update old-secret --name db-password-old
```

**Automation Script:**
```python
#!/usr/bin/env python3
# credential_rotation.py
import openstack
from datetime import datetime, timedelta

conn = openstack.connect(cloud='production')

# Find expiring credentials (< 30 days)
for cred in conn.identity.application_credentials():
    if cred.expires_at:
        expires = datetime.fromisoformat(cred.expires_at)
        if expires - datetime.now() < timedelta(days=30):
            print(f"Warning: {cred.name} expires soon: {expires}")
            # Trigger notification
```

**Rotation Schedule:**
- **User passwords:** 90 days maximum
- **Application credentials:** 180 days maximum
- **Service account tokens:** 30 days
- **API keys:** 365 days maximum
- **SSH keys:** Annual rotation
- **Encryption keys:** Per compliance requirements (quarterly for restricted data)

---

### 1.4 Use Federated Identity

**Priority:** MEDIUM

**Requirement:** Integrate with enterprise identity providers for centralized authentication.

**OpenStack Implementation:**
```yaml
# Keystone federation with SAML
# In keystone.conf
[auth]
methods = password,token,saml2,mapped

[federation]
trusted_dashboard = https://horizon.example.com/dashboard/auth/websso/
sso_callback_template = /etc/keystone/sso_callback_template.html

[saml]
certfile = /etc/keystone/ssl/certs/signing_cert.pem
keyfile = /etc/keystone/ssl/private/signing_key.pem
idp_entity_id = https://idp.example.com/metadata
idp_sso_endpoint = https://idp.example.com/sso
```

**Supported Protocols:**
- **SAML 2.0:** Shibboleth, SimpleSAMLphp
- **OIDC:** Keycloak, Okta
- **LDAP/Active Directory:** FreeIPA integration
- **OAuth 2.0:** For API access

**Benefits:**
- Single sign-on (SSO) experience
- Centralized user lifecycle management
- Consistent password policies
- Reduced credential sprawl

---

### 1.5 Audit and Monitor Privileged Access

**Priority:** HIGH

**Requirement:** Log and monitor all administrative actions.

**OpenStack Implementation:**
```yaml
# Oslo messaging for audit notifications
# In service config (nova.conf, neutron.conf, etc.)
[oslo_messaging_notifications]
driver = messagingv2
transport_url = rabbit://guest:guest@rabbitmq:5672/
topics = notifications

[audit_middleware]
audit_map_file = /etc/nova/api_audit_map.conf
```

**CADF Event Format:**
```json
{
  "typeURI": "http://schemas.dmtf.org/cloud/audit/1.0/event",
  "id": "unique-event-id",
  "eventType": "activity",
  "action": "delete",
  "outcome": "success",
  "initiator": {
    "typeURI": "service/security/account/user",
    "id": "alice",
    "host": {"address": "192.168.1.100"}
  },
  "target": {
    "typeURI": "compute/server",
    "id": "instance-uuid"
  },
  "observer": {
    "id": "nova-api"
  }
}
```

**Monitoring Setup:**
```bash
# ELK Stack for audit log aggregation
# Logstash pipeline
input {
  rabbitmq {
    host => "rabbitmq"
    queue => "audit.notifications"
  }
}

filter {
  json { source => "message" }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "openstack-audit-%{+YYYY.MM.dd}"
  }
}
```

---

## 2. Network Security

### 2.1 Implement Network Segmentation

**Priority:** CRITICAL

**Requirement:** Isolate workloads using network segmentation and security zones.

**OpenStack Implementation:**
```bash
# Create isolated networks for different tiers
openstack network create dmz-network --provider-network-type vlan \
  --provider-physical-network physnet1 --provider-segment 100

openstack network create app-network --provider-network-type vxlan

openstack network create data-network --provider-network-type vxlan \
  --disable-port-security

# Create subnets
openstack subnet create dmz-subnet --network dmz-network \
  --subnet-range 10.1.0.0/24 --no-dhcp

openstack subnet create app-subnet --network app-network \
  --subnet-range 10.2.0.0/24

openstack subnet create data-subnet --network data-network \
  --subnet-range 10.3.0.0/24
```

**Network Zones:**
1. **DMZ Zone:** Internet-facing services
2. **Application Zone:** Business logic tier
3. **Data Zone:** Database and storage tier
4. **Management Zone:** Administrative access
5. **Security Zone:** Security tools (IDS/IPS, scanners)

**Routing Restrictions:**
```bash
# Disable routing between data and DMZ zones
# No router between networks
# Use security groups to enforce

# Allow only specific inter-zone traffic
openstack security group rule create app-to-data-sg \
  --protocol tcp --dst-port 3306 --remote-group data-sg
```

---

### 2.2 Configure Security Groups with Default Deny

**Priority:** CRITICAL

**Requirement:** Implement default-deny security groups and explicitly allow required traffic.

**OpenStack Implementation:**
```bash
# Create default-deny security group
openstack security group create default-deny \
  --description "Default deny all traffic"

# Remove default egress rules
openstack security group rule list default-deny -f value -c ID | \
  xargs -I {} openstack security group rule delete {}

# Add specific allow rules
openstack security group rule create default-deny \
  --protocol tcp --dst-port 443 --remote-ip 0.0.0.0/0 \
  --description "Allow HTTPS inbound"

openstack security group rule create default-deny \
  --protocol tcp --dst-port 22 --remote-ip 10.0.0.0/8 \
  --description "Allow SSH from corporate network"

# Egress rules (whitelist approach)
openstack security group rule create default-deny \
  --egress --protocol tcp --dst-port 443 \
  --remote-ip 0.0.0.0/0 \
  --description "Allow HTTPS outbound"
```

**Template Security Groups:**
```yaml
# Heat template for security groups
resources:
  web_sg:
    type: OS::Neutron::SecurityGroup
    properties:
      name: web-tier-sg
      rules:
        - protocol: tcp
          port_range_min: 443
          port_range_max: 443
          remote_ip_prefix: 0.0.0.0/0
        - protocol: tcp
          port_range_min: 80
          port_range_max: 80
          remote_ip_prefix: 0.0.0.0/0

  app_sg:
    type: OS::Neutron::SecurityGroup
    properties:
      name: app-tier-sg
      rules:
        - protocol: tcp
          port_range_min: 8080
          port_range_max: 8080
          remote_group: { get_resource: web_sg }
```

**Best Practices:**
- Maximum specificity: Limit by protocol, port, and source
- Document each rule's purpose
- Regular security group audits (monthly)
- Remove unused security groups
- Use security group names, not IDs in rules

---

### 2.3 Enable Network Flow Logging

**Priority:** HIGH

**Requirement:** Capture network flow logs for security analysis and forensics.

**OpenStack Implementation:**
```bash
# Enable Neutron port logging
openstack network log create --resource-type security_group \
  --resource sg-uuid --event ALL \
  --name security-group-logs

# Configure logging for specific ports
openstack network log create --resource-type port \
  --resource port-uuid --event ALL \
  --name port-flow-logs
```

**Integration with ELK:**
```yaml
# Logstash pipeline for flow logs
input {
  file {
    path => "/var/log/neutron/security-group-*.log"
    type => "neutron-flows"
  }
}

filter {
  grok {
    match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{WORD:action} %{IP:src_ip}:%{NUMBER:src_port} -> %{IP:dst_ip}:%{NUMBER:dst_port} %{WORD:protocol}" }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "neutron-flows-%{+YYYY.MM.dd}"
  }
}
```

**Alternative Solutions:**
- **sFlow:** Neutron sFlow agent for NetFlow-like data
- **IPFIX:** IP Flow Information Export
- **Suricata:** Full packet capture and analysis
- **Zeek (Bro):** Network security monitoring

---

### 2.4 Implement Network Intrusion Detection/Prevention

**Priority:** HIGH

**Requirement:** Deploy IDS/IPS to detect and prevent network-based attacks.

**OpenStack Implementation:**

**Suricata Deployment:**
```bash
# Install Suricata on network nodes
apt-get install suricata

# Configure for OpenStack traffic
# /etc/suricata/suricata.yaml
af-packet:
  - interface: br-ex
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

# Enable rulesets
suricata-update enable-source et/open
suricata-update enable-source oisf/trafficid
suricata-update
```

**Snort Integration:**
```bash
# Snort inline mode with OpenStack
# Bridge mode on compute nodes
iptables -t mangle -A PREROUTING -j NFQUEUE --queue-num 0

# Snort config
config daq: nfq
config daq_mode: inline
```

**Custom Rules for OpenStack:**
```
# Detect API brute force
alert tcp any any -> $KEYSTONE_API 5000 (msg:"Keystone brute force detected"; \
  detection_filter:track by_src, count 20, seconds 60; sid:1000001;)

# Detect metadata service abuse
alert tcp any any -> 169.254.169.254 80 (msg:"Metadata service suspicious access"; \
  threshold:type threshold, track by_src, count 50, seconds 10; sid:1000002;)

# Detect nova-compute API anomalies
alert tcp any any -> $NOVA_API 8774 (msg:"Nova API suspicious POST"; \
  content:"POST"; http_method; content:"/servers"; http_uri; sid:1000003;)
```

**Alert Integration:**
```python
# Forward Suricata alerts to SIEM
# /etc/suricata/suricata.yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: unix_stream
      filename: /var/run/suricata/eve.sock
      types:
        - alert
        - http
        - dns
        - tls
```

---

### 2.5 Use Private Subnets for Backend Services

**Priority:** MEDIUM

**Requirement:** Deploy backend services in private subnets without direct internet access.

**OpenStack Implementation:**
```bash
# Create private network for databases
openstack network create private-db-network

openstack subnet create private-db-subnet \
  --network private-db-network \
  --subnet-range 192.168.100.0/24 \
  --no-gateway \
  --dns-nameserver 192.168.1.10

# Create NAT gateway for outbound (if needed)
openstack router create nat-gateway
openstack router add subnet nat-gateway private-db-subnet
openstack router set nat-gateway --external-gateway public-network
```

**Bastion Host Access:**
```bash
# Create bastion/jump host in DMZ
openstack server create bastion \
  --image ubuntu-20.04 \
  --flavor m1.small \
  --network dmz-network \
  --security-group bastion-sg \
  --key-name admin-key

# Bastion security group
openstack security group rule create bastion-sg \
  --protocol tcp --dst-port 22 --remote-ip <corp-ip>/32
```

---

## 3. Compute Security

### 3.1 Enable Instance Encryption

**Priority:** HIGH

**Requirement:** Encrypt instance ephemeral storage and volumes.

**OpenStack Implementation:**
```bash
# Create encrypted volume type
openstack volume type create encrypted-volumes \
  --encryption-provider luks \
  --encryption-cipher aes-xts-plain64 \
  --encryption-key-size 512 \
  --encryption-control-location front-end

# Create encrypted instance with encrypted volume
openstack server create secure-instance \
  --image ubuntu-20.04 \
  --flavor m1.medium \
  --boot-from-volume 20 \
  --volume-type encrypted-volumes \
  --key-name mykey

# Enable Nova ephemeral encryption
# In nova.conf
[ephemeral_storage_encryption]
enabled = True
cipher = aes-xts-plain64
key_size = 512
```

**Barbican Integration:**
```bash
# Store encryption keys in Barbican
openstack secret store --name instance-key \
  --payload-content-type "application/octet-stream" \
  --payload $(openssl rand -base64 32)

# Reference in volume creation
openstack volume create secure-vol --size 50 \
  --type encrypted-volumes \
  --property encryption_key_id=<barbican-secret-id>
```

---

### 3.2 Implement Secure Boot and Trusted Compute

**Priority:** MEDIUM

**Requirement:** Use secure boot and measured boot for instance integrity.

**OpenStack Implementation:**
```bash
# Create image with secure boot enabled
openstack image create ubuntu-secure \
  --file ubuntu-20.04.qcow2 \
  --disk-format qcow2 \
  --property os_secure_boot=required

# Enable TPM for measured boot
openstack flavor create m1.trusted \
  --ram 4096 --disk 40 --vcpus 2 \
  --property hw:tpm_version=2.0 \
  --property hw:tpm_model=tpm-crb

# Launch trusted instance
openstack server create trusted-vm \
  --image ubuntu-secure \
  --flavor m1.trusted \
  --key-name mykey
```

**Attestation with Keylime:**
```yaml
# Keylime agent configuration
# /etc/keylime/agent.conf
[cloud_agent]
cloudagent_ip = 0.0.0.0
cloudagent_port = 9002
tpm_ownerpassword = <owner-password>

[registrar]
registrar_ip = <registrar-ip>
registrar_port = 8890
```

---

### 3.3 Harden Instance Images

**Priority:** HIGH

**Requirement:** Use hardened, minimal base images with security updates.

**OpenStack Implementation:**
```bash
# Build hardened image with Packer
packer build -var 'source_image=ubuntu-20.04' hardened-ubuntu.json

# Apply CIS benchmarks
ansible-playbook -i inventory cis-ubuntu-hardening.yml

# Upload hardened image
openstack image create ubuntu-hardened \
  --file ubuntu-hardened.qcow2 \
  --disk-format qcow2 \
  --min-disk 10 \
  --min-ram 512 \
  --property os_distro=ubuntu \
  --property os_version=20.04 \
  --property security_hardened=cis-level-2

# Sign image for verification
openstack image set ubuntu-hardened \
  --signature $(openssl dgst -sha256 -sign private.pem ubuntu-hardened.qcow2 | base64)
```

**Image Hardening Checklist:**
- [ ] Minimal package installation
- [ ] Remove unnecessary services
- [ ] Configure SELinux/AppArmor
- [ ] Disable root login
- [ ] Configure firewall (iptables/nftables)
- [ ] Set strong password policies
- [ ] Configure audit logging (auditd)
- [ ] Enable automatic security updates
- [ ] Remove default credentials
- [ ] Disable unnecessary kernel modules

**Automated Hardening Tools:**
- **OpenSCAP:** Security compliance scanning
- **Lynis:** Security auditing tool
- **CIS-CAT:** CIS benchmark assessment
- **Ansible Hardening Roles:** Dev-Sec project

```bash
# OpenSCAP scanning
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
  --results scan-results.xml \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml
```

---

### 3.4 Implement Host-Based Intrusion Detection

**Priority:** MEDIUM

**Requirement:** Deploy HIDS on all compute instances.

**OpenStack Implementation:**

**OSSEC/Wazuh Deployment:**
```bash
# Install Wazuh agent on instances via cloud-init
#cloud-config
packages:
  - wazuh-agent

runcmd:
  - echo "WAZUH_MANAGER='wazuh-manager.example.com'" >> /etc/ossec-init.conf
  - systemctl enable wazuh-agent
  - systemctl start wazuh-agent
```

**Wazuh Rules for OpenStack:**
```xml
<!-- /var/ossec/etc/rules/openstack_rules.xml -->
<group name="openstack,">
  <rule id="100001" level="5">
    <if_sid>5715</if_sid>
    <match>nova-compute</match>
    <description>OpenStack Nova compute service activity</description>
  </rule>
  
  <rule id="100002" level="10">
    <if_sid>5503</if_sid>
    <match>metadata service</match>
    <description>Suspicious metadata service access</description>
  </rule>
</group>
```

**Alternative HIDS:**
- **AIDE:** Advanced Intrusion Detection Environment
- **Samhain:** File integrity and host-based IDS
- **Tripwire:** File integrity monitoring
- **Falco:** Runtime security for containers

---

### 3.5 Enable Instance Logging

**Priority:** HIGH

**Requirement:** Capture instance console logs and system logs centrally.

**OpenStack Implementation:**
```bash
# Enable serial console logging
# In nova.conf
[serial_console]
enabled = True
base_url = ws://controller:6083/
listen = 0.0.0.0
proxyclient_address = 192.168.1.10

# View console logs
openstack console log show <instance-id>
```

**Centralized Logging with Rsyslog:**
```bash
# Cloud-init configuration for instances
#cloud-config
write_files:
  - path: /etc/rsyslog.d/50-openstack.conf
    content: |
      *.* @@logserver.example.com:514
      
runcmd:
  - systemctl restart rsyslog
```

**Fluentd Agent:**
```yaml
# /etc/fluent/fluent.conf
<source>
  @type tail
  path /var/log/syslog
  pos_file /var/log/td-agent/syslog.pos
  tag openstack.instance
  <parse>
    @type syslog
  </parse>
</source>

<match openstack.**>
  @type elasticsearch
  host elasticsearch.example.com
  port 9200
  index_name openstack-logs
  type_name _doc
</match>
```

---

## 4. Storage Security

### 4.1 Enable Encryption at Rest

**Priority:** CRITICAL

**Requirement:** Encrypt all persistent storage volumes and object storage.

**OpenStack Implementation:**

**Cinder Volume Encryption:**
```bash
# Enable LUKS encryption for Cinder
# In cinder.conf
[key_manager]
backend = barbican

# Create encrypted volume type
openstack volume type create LUKS \
  --encryption-provider luks \
  --encryption-cipher aes-xts-plain64 \
  --encryption-key-size 256 \
  --encryption-control-location front-end

# All volumes of this type are automatically encrypted
openstack volume create encrypted-vol --size 100 --type LUKS
```

**Swift Object Encryption:**
```bash
# Enable server-side encryption
# In proxy-server.conf
[filter:encryption]
paste.filter_factory = swift.common.middleware.crypto:filter_factory

[pipeline:main]
pipeline = ... encryption ... proxy-server

# Client-side encryption option
swift upload container file.txt --header "X-Object-Meta-Encryption:AES256"
```

**Manila Share Encryption:**
```bash
# Create encrypted share type
manila type-create encrypted-shares True \
  --extra-specs encryption=True

manila create NFS 100 --share-type encrypted-shares \
  --name encrypted-share
```

---

### 4.2 Implement Backup Encryption

**Priority:** HIGH

**Requirement:** Encrypt all backups with separate encryption keys.

**OpenStack Implementation:**
```bash
# Cinder backup encryption
# In cinder.conf
[DEFAULT]
backup_driver = cinder.backup.drivers.swift.SwiftBackupDriver
backup_swift_enable_progress_timer = True

[key_manager]
backend = barbican

# Create encrypted backup
openstack volume backup create volume-id \
  --name encrypted-backup \
  --encryption-key-id <barbican-key-id>
```

**Automated Backup with Encryption:**
```python
#!/usr/bin/env python3
# backup_volumes.py
import openstack
import barbican.client

conn = openstack.connect(cloud='production')
barbican = barbican.client.Client(session=conn.session)

# Generate unique encryption key for backup
secret = barbican.secrets.create(
    name=f'backup-key-{date}',
    algorithm='aes',
    bit_length=256,
    mode='cbc'
)
secret.store()

# Create encrypted backup
for volume in conn.block_storage.volumes():
    if volume.status == 'available':
        conn.block_storage.create_backup(
            volume_id=volume.id,
            name=f'backup-{volume.name}',
            encryption_key_id=secret.secret_ref
        )
```

---

### 4.3 Enable Access Logging for Object Storage

**Priority:** MEDIUM

**Requirement:** Log all access to object storage for audit and forensics.

**OpenStack Implementation:**
```bash
# Enable Swift access logging
# In proxy-server.conf
[filter:cname_lookup]
paste.filter_factory = swift.common.middleware.cname_lookup:filter_factory

[filter:logging]
paste.filter_factory = swift.common.middleware.access_logging:filter_factory
log_level = INFO
log_name = swift-proxy
log_facility = LOG_LOCAL0
log_headers = yes
log_msg_template = {client_ip} {method} {path} {status} {content_length} {ttfb}

# Access logs location
/var/log/swift/proxy-access.log
```

**Parse Swift Logs:**
```bash
# Logstash grok pattern
%{IPORHOST:client_ip} %{WORD:method} %{URIPATH:path} %{NUMBER:status} %{NUMBER:content_length} %{NUMBER:ttfb}
```

---

### 4.4 Implement Storage Quotas

**Priority:** MEDIUM

**Requirement:** Set quotas to prevent resource exhaustion and cost overruns.

**OpenStack Implementation:**
```bash
# Set Cinder quotas
openstack quota set --volumes 50 --gigabytes 5000 <project-id>
openstack quota set --backups 20 --backup-gigabytes 1000 <project-id>

# Set Swift quotas
swift post container_name -m quota-bytes:10737418240  # 10GB

# Per-project quotas
openstack quota set --properties 1000 <project-id>
```

**Quota Monitoring:**
```python
#!/usr/bin/env python3
# check_quotas.py
import openstack

conn = openstack.connect(cloud='production')

for project in conn.identity.projects():
    quota = conn.block_storage.get_quota_set(project.id)
    usage = conn.block_storage.get_quota_set(project.id, usage=True)
    
    volume_usage_pct = (usage.volumes.in_use / quota.volumes.limit) * 100
    
    if volume_usage_pct > 80:
        print(f"WARNING: Project {project.name} at {volume_usage_pct}% volume quota")
```

---

## 5. Data Protection

### 5.1 Enable Deletion Protection

**Priority:** MEDIUM

**Requirement:** Prevent accidental deletion of critical resources.

**OpenStack Implementation:**
```bash
# Enable volume deletion protection via metadata
openstack volume set volume-id \
  --property deletion_protected=true

# Custom policy to enforce
# In cinder policy.yaml
"volume:delete": "rule:admin_or_owner and not volume.metadata.deletion_protected:true"
```

**Immutable Backups:**
```bash
# Swift container with retention policy
swift post backup-container \
  -H "X-Container-Meta-Immutable:true" \
  -H "X-Delete-After:2592000"  # 30 days
```

---

### 5.2 Implement Data Loss Prevention

**Priority:** HIGH

**Requirement:** Scan data for sensitive information before storage.

**OpenStack Implementation:**

**Presidio Integration:**
```python
#!/usr/bin/env python3
# dlp_scanner.py
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

def scan_object(content):
    results = analyzer.analyze(
        text=content,
        entities=["CREDIT_CARD", "SSN", "PHONE_NUMBER", "EMAIL"],
        language='en'
    )
    
    if results:
        # Alert or block upload
        return False, results
    return True, None

# Swift middleware integration
class DLPMiddleware:
    def __call__(self, env, start_response):
        if env['REQUEST_METHOD'] == 'PUT':
            content = env['wsgi.input'].read()
            allowed, findings = scan_object(content.decode())
            
            if not allowed:
                start_response('403 Forbidden', [])
                return [b'Sensitive data detected']
        
        return self.app(env, start_response)
```

**OpenDLP Scanning:**
```bash
# Schedule DLP scans on Swift
opendlp-scan --storage swift \
  --container user-uploads \
  --patterns /etc/opendlp/patterns.xml \
  --action quarantine
```

---

### 5.3 Configure Backup Retention