# AAP Webhook Endpoint Setup Guide

This guide walks through setting up an Event-Driven Ansible (EDA) webhook endpoint in Ansible Automation Platform (AAP) to receive alerts from Prometheus Alertmanager and trigger remediation playbooks.

## Prerequisites

- Access to AAP UI with admin privileges
- Service account user created in AAP (for webhook authentication)
- Remediation playbook (`restart-frr-bgp-agent.yml`) already in AAP
- Vault access (for storing the service account token)
- External Secrets Operator (ESO) configured in your cluster

## Overview

The setup flow:
1. Create a Job Template in AAP for the remediation playbook
2. Generate/retrieve API token for the service account
3. Store token in Vault
4. Configure ESO to sync token to Kubernetes
5. Update AlertmanagerConfig with the webhook URL
6. Test the webhook endpoint

---

## Step 1: Create Job Template in AAP

1. **Log into AAP UI** as an admin user

2. **Navigate to Templates**:
   - Go to **Resources** → **Templates**
   - Click **Add** → **Add job template**

3. **Configure Job Template**:
   - **Name**: `SDN BGP Daemon Remediation`
   - **Job Type**: `Run`
   - **Inventory**: Select your SDN nodes inventory (or create one)
   - **Project**: Select project containing `restart-frr-bgp-agent.yml`
   - **Playbook**: `restart-frr-bgp-agent.yml`
   - **Credentials**: Add any required credentials (SSH keys, etc.)
   - **Variables**: 
     - Enable **Prompt on launch** for `node_name` variable
     - This allows the webhook to pass the node name dynamically
   - **Options**: 
     - Enable **Enable Webhook** (important!)
     - Enable **Enable Concurrent Jobs** if you want multiple remediations to run simultaneously
   - Click **Save**

4. **Get Job Template ID**:
   - After saving, note the **Job Template ID** from the URL or template details
   - Example: If URL is `https://aap.example.com/#/templates/job_template/123`, the ID is `123`
   - You'll need this for the webhook URL

---

## Step 2: Generate API Token for Service Account

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
   - Token format: `abc123def456...` (long alphanumeric string)

4. **Verify Token Permissions**:
   - Ensure the service account user has:
     - **Execute** permission on the Job Template
     - **Admin** or **Execute** permission on the Inventory
     - **Read** permission on the Project

---

## Step 3: Store Token in Vault

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
   - You'll need this for the ExternalSecret configuration

---

## Step 4: Configure External Secrets Operator (ESO)

1. **Create ExternalSecret** (if not already created):

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

4. **Check Secret Contents** (base64 decoded):
   ```bash
   kubectl get secret eda-aap-token -n monitoring -o jsonpath='{.data.token}' | base64 -d
   ```

---

## Step 5: Update AlertmanagerConfig

1. **Get AAP Webhook URL**:
   - Format: `https://<aap-hostname>/api/v2/job_templates/<JOB_TEMPLATE_ID>/launch/`
   - Example: `https://aap.example.com/api/v2/job_templates/123/launch/`

2. **Update `kubernetes/alertmanager-config.yaml`**:
   - Replace `http://your-eda-aap-endpoint/api/v2/job_templates/YOUR_TEMPLATE_ID/launch/` with your actual URL
   - Ensure the URL uses `https://` if AAP uses SSL

3. **Verify Secret Reference**:
   - The AlertmanagerConfig should reference:
     ```yaml
     authorization:
       type: Bearer
       credentials:
         name: eda-aap-token
         key: token
     ```

4. **Apply AlertmanagerConfig**:
   ```bash
   kubectl apply -f kubernetes/alertmanager-config.yaml
   ```

5. **Verify Alertmanager Picked Up Config**:
   ```bash
   kubectl get alertmanagerconfig sdn-node-monitor-alertmanager-config -n monitoring
   # Check Alertmanager pods logs for any errors
   kubectl logs -n monitoring -l app.kubernetes.io/name=alertmanager
   ```

---

## Step 6: Configure Job Template to Accept Webhook Payload

1. **In AAP UI**, go back to your Job Template

2. **Configure Extra Variables**:
   - The playbook expects `node_name` in `extra_vars`
   - The AlertmanagerConfig sends it as:
     ```json
     {
       "extra_vars": {
         "node_name": "{{ .CommonLabels.node }}",
         ...
       }
     }
     ```
   - AAP will automatically extract `extra_vars` from the webhook payload

3. **Enable Webhook Authentication** (if not already enabled):
   - In Job Template → **Options** → Ensure **Enable Webhook** is checked
   - **Webhook Service**: `GitLab`, `GitHub`, or `Generic` (use Generic for Alertmanager)

4. **Get Webhook URL** (for testing):
   - Job Template → **Details** → **Webhooks** section
   - Copy the webhook URL (different from API launch URL)
   - Format: `https://aap.example.com/api/v2/job_templates/<ID>/callback/`

---

## Step 7: Test the Webhook

### Option A: Test via Alertmanager (Recommended)

1. **Trigger Test Alert**:
   - Set `TEST_MODE=on` in your monitoring container to force condition
   - Or wait for a real FRR daemon failure
   - Check Prometheus alerts: `sdn_bgp_daemon_down > 0`

2. **Verify Alert Fired**:
   ```bash
   # Check Alertmanager UI or logs
   kubectl logs -n monitoring -l app.kubernetes.io/name=alertmanager | grep SDNBGPDaemonDown
   ```

3. **Check AAP Job Execution**:
   - In AAP UI → **Jobs** → Look for recently launched jobs
   - Verify the job was triggered
   - Check job output for successful remediation

### Option B: Test via curl (Manual)

1. **Get Token from Secret**:
   ```bash
   TOKEN=$(kubectl get secret eda-aap-token -n monitoring -o jsonpath='{.data.token}' | base64 -d)
   ```

2. **Send Test Webhook**:
   ```bash
   curl -X POST \
     https://aap.example.com/api/v2/job_templates/123/launch/ \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "extra_vars": {
         "node_name": "test-node.example.com",
         "alert_name": "SDNBGPDaemonDown",
         "severity": "critical"
       }
     }'
   ```

3. **Verify Job Launched**:
   - Check AAP UI → **Jobs** for the new job
   - Verify `node_name` was passed correctly

---

## Step 8: Verify End-to-End Flow

1. **Monitor Container** → Detects FRR daemon down
2. **Prometheus** → Scrapes metric `sdn_bgp_daemon_down{node="..."}`
3. **PrometheusRule** → Fires alert `SDNBGPDaemonDown`
4. **Alertmanager** → Routes to `eda-aap-webhook` receiver
5. **AlertmanagerConfig** → Sends webhook to AAP with Bearer token
6. **AAP** → Launches Job Template with `node_name` from alert
7. **Playbook** → Executes remediation on target node

---

## Troubleshooting

### Webhook Not Receiving Alerts

1. **Check AlertmanagerConfig**:
   ```bash
   kubectl get alertmanagerconfig -n monitoring
   kubectl describe alertmanagerconfig sdn-node-monitor-alertmanager-config -n monitoring
   ```

2. **Check Alertmanager Logs**:
   ```bash
   kubectl logs -n monitoring -l app.kubernetes.io/name=alertmanager | grep -i webhook
   kubectl logs -n monitoring -l app.kubernetes.io/name=alertmanager | grep -i error
   ```

3. **Verify Route Matchers**:
   - Ensure `alertname: SDNBGPDaemonDown` matches your PrometheusRule
   - Check `component: bgp` label is present in alert

### Token Authentication Fails

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

### Job Template Not Launching

1. **Check AAP Job Template Permissions**:
   - Service account user needs **Execute** permission
   - Verify in AAP UI → Job Template → **Access** tab

2. **Check Webhook Payload**:
   - Review Alertmanager logs for the actual payload sent
   - Verify `extra_vars.node_name` is present

3. **Check AAP API Logs**:
   - In AAP UI → **Settings** → **System Activity Stream**
   - Look for webhook/API call failures

### Playbook Not Receiving node_name

1. **Verify AlertmanagerConfig Body Template**:
   - Ensure `{{ .CommonLabels.node }}` is correct
   - The `node` label comes from the Prometheus metric

2. **Check Metric Labels**:
   ```bash
   curl http://<node-ip>:8989/metrics | grep sdn_bgp_daemon_down
   # Should show: sdn_bgp_daemon_down{node="..."} 1
   ```

3. **Test with Manual Extra Vars**:
   - In AAP UI, manually launch job with `node_name` extra var
   - Verify playbook receives it correctly

---

## Security Considerations

1. **Token Rotation**:
   - Rotate API tokens periodically
   - Update in Vault, ESO will sync automatically

2. **Least Privilege**:
   - Service account should only have permissions needed for remediation
   - Consider creating a custom role instead of admin

3. **Network Security**:
   - Ensure Alertmanager can reach AAP endpoint
   - Use HTTPS for webhook URLs
   - Consider network policies if using them

4. **Secret Management**:
   - Never commit tokens to git
   - Use Vault + ESO for all secrets
   - Regularly audit secret access

---

## Next Steps

- [ ] Set up monitoring and alerting for the remediation jobs
- [ ] Create runbooks for common failure scenarios
- [ ] Implement alerting on remediation job failures
- [ ] Set up token rotation schedule
- [ ] Document playbook execution results and metrics

---

## References

- [AAP API Documentation](https://docs.ansible.com/automation-controller/latest/html/userguide/webhooks.html)
- [Alertmanager Webhook Configuration](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config)
- [External Secrets Operator](https://external-secrets.io/)
- [Vault Documentation](https://www.vaultproject.io/docs)
