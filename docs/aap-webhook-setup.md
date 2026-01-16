# EDA Webhook Endpoint Setup Guide

This guide walks through setting up an Event-Driven Ansible (EDA) webhook endpoint to receive alerts from Prometheus Alertmanager and trigger remediation playbooks.

## Prerequisites

- Event-Driven Ansible (EDA) installed and running
- Access to EDA UI/API
- Service account user created in AAP (for playbook execution)
- Remediation playbook (`restart-frr-bgp-agent.yml`) already in AAP
- Vault access (for storing the service account token)
- External Secrets Operator (ESO) configured in your cluster

## Overview

The setup flow:
1. Create/configure EDA webhook endpoint
2. Create EDA rulebook to process Alertmanager events
3. Generate/retrieve API token for the service account
4. Store token in Vault
5. Configure ESO to sync token to Kubernetes
6. Update AlertmanagerConfig with the EDA webhook URL
7. Test the webhook endpoint

---

## Step 1: Create EDA Webhook Endpoint

### Option A: Using EDA UI

1. **Log into EDA UI** (if available)

2. **Navigate to Webhooks**:
   - Go to **Webhooks** or **Event Sources**
   - Click **Add** → **Add Webhook**

3. **Configure Webhook**:
   - **Name**: `sdn-bgp-daemon-alerts`
   - **Type**: `Webhook` or `HTTP`
   - **Port**: `5000` (default) or your configured port
   - **Path**: `/webhook/sdn-bgp-daemon` (customize as needed)
   - **Authentication**: 
     - Enable **Token Authentication** (recommended)
     - Or use **Basic Auth** (less secure)
   - **Enable**: Check to activate
   - Click **Save**

4. **Get Webhook URL**:
   - Full URL format: `http://<eda-hostname>:<port>/webhook/sdn-bgp-daemon`
   - Example: `http://eda.example.com:5000/webhook/sdn-bgp-daemon`
   - Note this URL for AlertmanagerConfig

### Option B: Using EDA CLI/Configuration

1. **Create Webhook Configuration File** (`eda-webhook-config.yml`):

   ```yaml
   # EDA Webhook Event Source Configuration
   event_source:
     name: sdn-bgp-daemon-webhook
     source:
       plugin: ansible.eda.webhook
       host: 0.0.0.0
       port: 5000
       paths:
         - /webhook/sdn-bgp-daemon
     # Optional: Token authentication
     # token: "your-webhook-token-here"
   ```

2. **Deploy Webhook**:
   ```bash
   # If using EDA CLI
   ansible-eda webhook start --config eda-webhook-config.yml
   
   # Or if using EDA as a service
   # Add configuration to EDA configuration directory
   ```

3. **Verify Webhook is Running**:
   ```bash
   curl http://eda.example.com:5000/webhook/sdn-bgp-daemon
   # Should return 200 OK or similar
   ```

---

## Step 2: Create EDA Rulebook

The rulebook defines how EDA processes incoming events and triggers playbooks.

1. **Create Rulebook File** (`sdn-bgp-remediation-rulebook.yml`):

   ```yaml
   ---
   - name: SDN BGP Daemon Remediation Rulebook
     hosts: localhost
     sources:
       - ansible.eda.webhook:
           host: 0.0.0.0
           port: 5000
           paths:
             - /webhook/sdn-bgp-daemon
           # Optional token authentication (set via env var)
           # token: "{{ lookup('env', 'EDA_WEBHOOK_TOKEN') }}"
     
     rules:
       - name: Process SDN BGP Daemon Down Alert
         # Alertmanager sends labels under commonLabels and alerts[0].labels
         # Use a single expression (no list) to avoid parser errors
         condition: >
           event.commonLabels.alertname == "SDNBGPDaemonDown"
           and event.commonLabels.component == "bgp"
         action:
           run_job_template:
             name: "SDN BGP Daemon Remediation"
             organization: "Default"
             inventory: "SDN Nodes Inventory"
             extra_vars:
               node_name: "{{ event.commonLabels.node | default(event.alerts[0].labels.node | default(event.alerts[0].annotations.eda_node)) }}"
               alert_name: "{{ event.commonLabels.alertname | default(event.alerts[0].labels.alertname) }}"
               severity: "{{ event.commonLabels.severity | default(event.alerts[0].labels.severity) }}"
               eda_action: "{{ event.alerts[0].annotations.eda_action | default('remediate_bgp') }}"
               eda_playbook: "{{ event.alerts[0].annotations.eda_playbook | default('restart-frr-bgp-agent.yml') }}"
   ```

2. **Alternative Rulebook Format** (if using different EDA structure):

   ```yaml
   ---
   - name: Listen for SDN BGP alerts
     hosts: localhost
     sources:
       - ansible.eda.webhook:
           host: 0.0.0.0
           port: 5000
     rules:
       - name: SDN BGP Daemon Down
         condition: >
           event.commonLabels.alertname == "SDNBGPDaemonDown"
         action:
           run_job_template:
             name: "SDN BGP Daemon Remediation"
             organization: "Default"
             inventory: "SDN Nodes Inventory"
             extra_vars:
               node_name: "{{ event.commonLabels.node | default(event.alerts[0].labels.node | default(event.alerts[0].annotations.eda_node)) }}"
   ```

3. **Deploy Rulebook to EDA**:

   ```bash
   # If using EDA CLI
   ansible-rulebook --rulebook sdn-bgp-remediation-rulebook.yml
   
   # Or if using EDA as a service
   # Copy rulebook to EDA rulebooks directory
   # EDA will automatically pick it up
   ```

4. **Verify Rulebook is Active**:
   - Check EDA logs for rulebook loading
   - Verify webhook endpoint is listening

---

## Step 3: Create Job Template in AAP (for Playbook Execution)

1. **Log into AAP UI** as an admin user

2. **Navigate to Templates**:
   - Go to **Resources** → **Templates**
   - Click **Add** → **Add job template**

3. **Configure Job Template**:
   - **Name**: `SDN BGP Daemon Remediation`
   - **Job Type**: `Run`
   - **Inventory**: Select your SDN nodes inventory
   - **Project**: Select project containing `restart-frr-bgp-agent.yml`
   - **Playbook**: `restart-frr-bgp-agent.yml`
   - **Credentials**: Add any required credentials (SSH keys, etc.)
   - **Variables**: 
     - Enable **Prompt on launch** for `node_name` variable
   - Click **Save**

4. **Grant Permissions**:
   - Ensure the service account user has **Execute** permission on this Job Template
   - Go to Job Template → **Access** → Add service account with **Execute** role

---

## Step 4: Generate API Token for Service Account

1. **Log into AAP UI** as the service account user (or as admin)

2. **Navigate to User Settings**:
   - Click on your username (top right) → **User Details**
   - Or go to **Users** → Select your service account user

3. **Create API Token**:
   - Scroll to **API Tokens** section
   - Click **+** (Add token)
   - **Description**: `EDA Webhook Token for SDN Monitoring`
   - **Scope**: `Write` (needs to launch job templates)
   - Click **Generate**
   - **IMPORTANT**: Copy the token immediately - you won't be able to see it again!

4. **Verify Token Permissions**:
   - Ensure the service account user has:
     - **Execute** permission on the Job Template
     - **Admin** or **Execute** permission on the Inventory
     - **Read** permission on the Project

---

## Step 5: Store Token in Vault

1. **Access Vault** (via CLI or UI)

2. **Store the Token**:
   ```bash
   vault kv put secret/data/aap/eda-webhook \
     token="<your-api-token-here>"
   ```

3. **Verify**:
   ```bash
   vault kv get secret/data/aap/eda-webhook
   ```

4. **Note the Vault Path**:
   - Path: `secret/data/aap/eda-webhook`
   - Property: `token`

---

## Step 6: Configure External Secrets Operator (ESO)

1. **Create ExternalSecret**:

   ```yaml
   apiVersion: external-secrets.io/v1beta1
   kind: ExternalSecret
   metadata:
     name: eda-aap-token
     namespace: monitoring
   spec:
     refreshInterval: 1h  # Refresh token every hour
     secretStoreRef:
       name: vault-backend  # Your ESO SecretStore pointing to Vault
       kind: SecretStore
     target:
       name: eda-aap-token
       creationPolicy: Owner
     data:
       - secretKey: token
         remoteRef:
           key: secret/data/aap/eda-webhook  # Path in Vault
           property: token  # Property name in Vault secret
   ```

2. **Apply the ExternalSecret**:
   ```bash
   kubectl apply -f externalsecret-eda-aap-token.yaml
   ```

3. **Verify Secret Created**:
   ```bash
   kubectl get secret eda-aap-token -n monitoring
   kubectl get externalsecret eda-aap-token -n monitoring
   ```

---

## Step 7: Update AlertmanagerConfig

1. **Get EDA Webhook URL**:
   - In AAP 2.5, the Rulebook Activation creates a Service, but **no Route**
   - You must expose the Service yourself:
     ```bash
     oc create route edge sdn-mon-webhook -n aap-instance \
       --service=sdn-mon-service \
       --port=5000 \
       --insecure-policy=Redirect
     ```
   - Then use the Route URL:
     `https://sdn-mon-webhook-aap-instance.apps.<domain>/webhook/sdn-bgp-daemon`

2. **Update `kubernetes/alertmanager-config.yaml`**:
   - Replace the URL with your EDA webhook endpoint
   - The body format should match what EDA expects (Alertmanager format)

3. **Verify Secret Reference**:
   - The AlertmanagerConfig should reference:
     ```yaml
     authorization:
       type: Bearer
       credentials:
         name: eda-aap-token
         key: token
     ```
   - **Note**: If EDA webhook uses token authentication, you may need a different secret
   - If EDA doesn't require auth, you can remove the authorization section

4. **Apply AlertmanagerConfig**:
   ```bash
   kubectl apply -f kubernetes/alertmanager-config.yaml
   ```

5. **Verify Alertmanager Picked Up Config**:
   ```bash
   kubectl get alertmanagerconfig sdn-node-monitor-alertmanager-config -n monitoring
   kubectl logs -n monitoring -l app.kubernetes.io/name=alertmanager
   ```

---

## Step 8: Configure EDA to Use AAP Token

If your EDA rulebook needs to call AAP APIs, configure it to use the token:

1. **Option A: Environment Variable**:
   ```bash
   export ANSIBLE_EDA_AAP_TOKEN=$(kubectl get secret eda-aap-token -n monitoring -o jsonpath='{.data.token}' | base64 -d)
   ```

2. **Option B: EDA Configuration File**:
   ```yaml
   # eda-config.yml
   aap:
     host: https://aap.example.com
     token: "{{ lookup('env', 'ANSIBLE_EDA_AAP_TOKEN') }}"
   ```

3. **Option C: Vault Integration** (if EDA supports it):
   - Configure EDA to read token from Vault directly
   - Or use ESO to sync to a location EDA can access

---

## Step 9: Test the Webhook

### Option A: Test via Alertmanager (Recommended)

1. **Trigger Test Alert**:
   - Set `TEST_MODE=on` in your monitoring container
   - Or wait for a real FRR daemon failure
   - Check Prometheus alerts: `sdn_bgp_daemon_down > 0`

2. **Verify Alert Fired**:
   ```bash
   kubectl logs -n monitoring -l app.kubernetes.io/name=alertmanager | grep SDNBGPDaemonDown
   ```

3. **Check EDA Received Event**:
   ```bash
   # Check EDA logs
   kubectl logs -n <eda-namespace> -l app=eda | grep webhook
   # Or check EDA UI for incoming events
   ```

4. **Check AAP Job Execution**:
   - In AAP UI → **Jobs** → Look for recently launched jobs
   - Verify the job was triggered by EDA
   - Check job output for successful remediation

### Option B: Test via curl (Manual)

1. **Get Token from Secret** (if EDA requires auth):
   ```bash
   TOKEN=$(kubectl get secret eda-aap-token -n monitoring -o jsonpath='{.data.token}' | base64 -d)
   ```

2. **Send Test Webhook to EDA**:
   ```bash
   curl -X POST \
     http://eda.example.com:5000/webhook/sdn-bgp-daemon \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{
       "alerts": [{
         "labels": {
           "alertname": "SDNBGPDaemonDown",
           "node": "test-node.example.com",
           "component": "bgp",
           "severity": "critical"
         },
         "annotations": {
           "summary": "FRR daemons are not running",
           "description": "Test alert",
           "eda_node": "test-node.example.com",
           "eda_action": "remediate_bgp",
           "eda_playbook": "restart-frr-bgp-agent.yml"
         }
       }],
       "commonLabels": {
         "node": "test-node.example.com",
         "alertname": "SDNBGPDaemonDown"
       },
       "groupLabels": {
         "alertname": "SDNBGPDaemonDown"
       }
     }'
   ```

3. **Verify EDA Processed Event**:
   - Check EDA logs for event processing
   - Verify rulebook matched the condition
   - Check if playbook was triggered

---

## Step 10: Verify End-to-End Flow

1. **Monitor Container** → Detects FRR daemon down
2. **Prometheus** → Scrapes metric `sdn_bgp_daemon_down{node="..."}`
3. **PrometheusRule** → Fires alert `SDNBGPDaemonDown`
4. **Alertmanager** → Routes to `eda-aap-webhook` receiver
5. **AlertmanagerConfig** → Sends webhook to EDA endpoint
6. **EDA** → Receives event, processes through rulebook
7. **EDA Rulebook** → Matches condition, triggers AAP Job Template
8. **AAP** → Launches playbook with `node_name` from event
9. **Playbook** → Executes remediation on target node

---

## Troubleshooting

### EDA Not Receiving Webhooks

1. **Check EDA Webhook Status**:
   ```bash
   # Check if EDA webhook is running
   curl http://eda.example.com:5000/webhook/sdn-bgp-daemon
   # Or check EDA service status
   kubectl get pods -n <eda-namespace> -l app=eda
   ```

2. **Check EDA Logs**:
   ```bash
   kubectl logs -n <eda-namespace> -l app=eda | grep webhook
   kubectl logs -n <eda-namespace> -l app=eda | grep error
   ```

3. **Verify Network Connectivity**:
   - Ensure Alertmanager can reach EDA endpoint
   - Check firewall/network policies
   - Verify DNS resolution

### EDA Rulebook Not Matching Events

1. **Check Rulebook Condition**:
   - Verify condition matches Alertmanager payload structure
   - Check event field names (may be nested differently)

2. **Enable Debug Logging**:
   ```yaml
   # In rulebook, add debug action
   action:
     debug:
       msg: "Received event: {{ event }}"
   ```

3. **Check Event Structure**:
   - Log incoming events to see actual structure
   - Adjust rulebook condition to match

### AAP Job Not Launching from EDA

1. **Check EDA-AAP Connection**:
   - Verify EDA can reach AAP API
   - Check AAP token is valid
   - Verify token has correct permissions

2. **Check EDA Logs for Errors**:
   ```bash
   kubectl logs -n <eda-namespace> -l app=eda | grep -i aap
   kubectl logs -n <eda-namespace> -l app=eda | grep -i error
   ```

3. **Verify Rulebook Action**:
   - Check `run_playbook` or `run_job_template` syntax
   - Verify organization, inventory names are correct
   - Check extra_vars are being passed correctly

### Token Authentication Issues

1. **Verify Secret Exists**:
   ```bash
   kubectl get secret eda-aap-token -n monitoring
   ```

2. **Check Token Validity**:
   ```bash
   TOKEN=$(kubectl get secret eda-aap-token -n monitoring -o jsonpath='{.data.token}' | base64 -d)
   curl -H "Authorization: Bearer $TOKEN" https://aap.example.com/api/v2/me/
   ```

3. **Verify ExternalSecret Status**:
   ```bash
   kubectl get externalsecret eda-aap-token -n monitoring
   kubectl describe externalsecret eda-aap-token -n monitoring
   ```

---

## Security Considerations

1. **Webhook Authentication**:
   - Enable token authentication on EDA webhook if possible
   - Use HTTPS for webhook endpoints
   - Consider IP whitelisting if supported

2. **Token Management**:
   - Rotate API tokens periodically
   - Update in Vault, ESO will sync automatically
   - Use least privilege for service account

3. **Network Security**:
   - Ensure Alertmanager can reach EDA endpoint
   - Use network policies if available
   - Encrypt traffic between components

4. **Secret Management**:
   - Never commit tokens to git
   - Use Vault + ESO for all secrets
   - Regularly audit secret access

---

## EDA-Specific Configuration Notes

1. **Event Format**:
   - EDA expects events in a specific format
   - Alertmanager sends webhook in its own format
   - Rulebook may need to transform event structure

2. **Rulebook Location**:
   - EDA may have specific directories for rulebooks
   - Check EDA documentation for deployment method
   - May need to restart EDA after rulebook changes

3. **AAP Integration**:
   - EDA can call AAP via API or ansible-runner
   - Verify which method your EDA installation uses
   - Configure AAP connection in EDA config

---

## Next Steps

- [ ] Set up monitoring for EDA event processing
- [ ] Create additional rulebooks for other alert types
- [ ] Implement alerting on remediation job failures
- [ ] Set up token rotation schedule
- [ ] Document EDA event processing metrics

---

## References

- [Event-Driven Ansible Documentation](https://ansible.readthedocs.io/projects/rulebook/)
- [EDA Webhook Plugin](https://github.com/ansible/event-driven-ansible)
- [Alertmanager Webhook Configuration](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config)
- [External Secrets Operator](https://external-secrets.io/)
- [Vault Documentation](https://www.vaultproject.io/docs)
