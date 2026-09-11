export interface Env {
  DB: D1Database;
  SN_INSTANCE_URL: string;
  SN_USER: string;
  SN_PASSWORD: string;
}

interface GrafanaAlert {
  status: 'firing' | 'resolved';
  fingerprint: string;
  labels: Record<string, string>;
  annotations: Record<string, string>;
}

interface GrafanaWebhookPayload {
  status: string;
  alerts: GrafanaAlert[];
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    try {
      const payload: GrafanaWebhookPayload = await request.json();
      const results = [];

      for (const alert of payload.alerts) {
        const alertUid = alert.fingerprint;
        
        // 1. Check local Cloudflare D1 state for an existing ServiceNow incident mapping
        const existing = await env.DB.prepare(
          `SELECT * FROM alert_incidents WHERE alert_uid = ?`
        ).bind(alertUid).first<{ sn_sys_id: string; sn_incident_number: string; status: string }>();

        if (alert.status === 'firing') {
          if (!existing) {
            // Create new Incident in ServiceNow
            const snResponse = await createIncInServiceNow(env, alert);
            if (snResponse) {
              await env.DB.prepare(
                `INSERT INTO alert_incidents (alert_uid, sn_sys_id, sn_incident_number, status, updated_at) VALUES (?, ?, ?, ?, datetime('now'))`
              ).bind(alertUid, snResponse.sys_id, snResponse.number, 'firing').run();
              results.push({ alertUid, action: 'created', incident: snResponse.number });
            }
          } else {
            results.push({ alertUid, action: 'skipped_already_exists', incident: existing.sn_incident_number });
          }
        } else if (alert.status === 'resolved') {
          if (existing && existing.sn_sys_id) {
            // Update / Close Incident in ServiceNow
            await updateIncInServiceNow(env, existing.sn_sys_id, 'resolved');
            await env.DB.prepare(
              `UPDATE alert_incidents SET status = 'resolved', updated_at = datetime('now') WHERE alert_uid = ?`
            ).bind(alertUid).run();
            results.push({ alertUid, action: 'resolved', incident: existing.sn_incident_number });
          } else {
            results.push({ alertUid, action: 'not_found_in_state' });
          }
        }
      }

      return new Response(JSON.stringify({ success: true, processed: results }), {
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (err: any) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  },
};

async function createIncInServiceNow(env: Env, alert: GrafanaAlert) {
  const url = `${env.SN_INSTANCE_URL}/api/now/table/incident`;
  const shortDesc = alert.annotations.summary || alert.labels.alertname || 'Grafana Alert Firing';
  const description = alert.annotations.description || JSON.stringify(alert.labels);

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Basic ' + btoa(`${env.SN_USER}:${env.SN_PASSWORD}`),
      'Accept': 'application/json',
    },
    body: JSON.stringify({
      short_description: shortDesc,
      description: description,
      urgency: '2',
      impact: '2',
      state: '2',//Work in Progress
    }),
  });

  if (!response.ok) {
    throw new Error(`ServiceNow API error: ${response.statusText}`);
  }

  const data: any = await response.json();
  return {
    sys_id: data.result.sys_id,
    number: data.result.number,
  };
}

async function updateIncInServiceNow(env: Env, sysId: string, state: string) {
  const url = `${env.SN_INSTANCE_URL}/api/now/table/incident/${sysId}`;
  
  // State 6 typically represents Resolved in baseline ITIL ServiceNow configurations
  const snState = state === 'resolved' ? '6' : '2';

  const response = await fetch(url, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Basic ' + btoa(`${env.SN_USER}:${env.SN_PASSWORD}`),
      'Accept': 'application/json',
    },
    body: JSON.stringify({
      state: snState,
      incident_state: snState,
      close_code: '10',
      close_notes: 'Automatically resolved via Grafana alert recovery webhook.',
      comments:'Automatically resolved via Grafana alert recovery webhook.',
    }),
  });

  if (!response.ok) {
    throw new Error(`ServiceNow Update error: ${response.statusText}`);
  }
}