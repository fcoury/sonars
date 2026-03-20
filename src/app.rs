use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Generator, Shell, generate};
use regex::Regex;
use serde::{Deserialize, Serialize};

const DEFAULT_COLUMNS: &[Column] = &[
    Column::Port,
    Column::Pid,
    Column::Process,
    Column::Container,
    Column::Image,
    Column::ContainerPort,
    Column::Url,
];

const ALL_COLUMNS: &[Column] = &[
    Column::Port,
    Column::Process,
    Column::Pid,
    Column::Type,
    Column::Url,
    Column::Cpu,
    Column::Mem,
    Column::Threads,
    Column::Uptime,
    Column::State,
    Column::Connections,
    Column::Container,
    Column::Image,
    Column::ContainerPort,
    Column::Compose,
    Column::Project,
    Column::User,
    Column::Bind,
    Column::Ip,
    Column::Health,
    Column::Latency,
];

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let context = ContextState {
        no_color: cli.no_color,
    };

    match cli.command {
        Commands::List(args) => list_command(&context, args),
        Commands::Info(args) => info_command(args),
        Commands::Kill(args) => kill_command(args),
        Commands::KillAll(args) => kill_all_command(args),
        Commands::Logs(args) => logs_command(args),
        Commands::Attach(args) => attach_command(args),
        Commands::Open(args) => open_command(args),
        Commands::Watch(args) => watch_command(&context, args),
        Commands::Graph(args) => graph_command(args),
        Commands::Map(args) => map_command(args),
        Commands::Profile(args) => profile_command(args),
        Commands::Up(args) => up_command(args),
        Commands::Down(args) => down_command(args),
        Commands::Version(args) => version_command(args),
        Commands::Completion(args) => completion_command(args),
    }
}

#[derive(Parser)]
#[command(
    name = "sonar",
    about = "Detect and manage services listening on localhost ports",
    version
)]
struct Cli {
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    no_color: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    List(ListArgs),
    Info(PortArg),
    Kill(KillArgs),
    KillAll(KillAllArgs),
    Logs(LogsArgs),
    Attach(AttachArgs),
    Open(PortArg),
    Watch(WatchArgs),
    Graph(GraphArgs),
    Map(MapArgs),
    Profile(ProfileArgs),
    Up(ProfileNameArg),
    Down(DownArgs),
    Version(VersionArgs),
    Completion(CompletionArgs),
}

#[derive(clap::Args)]
struct ListArgs {
    #[arg(long)]
    json: bool,
    #[arg(long)]
    filter: Option<PortFilter>,
    #[arg(long, default_value = "port")]
    sort: SortKey,
    #[arg(short = 'a', long)]
    all: bool,
    #[arg(short = 'c', long, value_delimiter = ',')]
    columns: Vec<Column>,
    #[arg(long)]
    all_columns: bool,
    #[arg(long)]
    health: bool,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    stats: bool,
}

#[derive(clap::Args)]
struct PortArg {
    port: u16,
    #[arg(long)]
    host: Option<String>,
}

#[derive(clap::Args)]
struct KillArgs {
    port: u16,
    #[arg(short = 'f', long)]
    force: bool,
}

#[derive(clap::Args)]
struct KillAllArgs {
    #[arg(long)]
    filter: Option<PortFilter>,
    #[arg(long)]
    project: Option<String>,
    #[arg(short = 'y', long)]
    yes: bool,
    #[arg(short = 'f', long)]
    force: bool,
    #[arg(short = 'a', long)]
    all: bool,
}

#[derive(clap::Args)]
struct LogsArgs {
    port: u16,
    #[arg(short = 'f', long, default_value_t = true)]
    follow: bool,
}

#[derive(clap::Args)]
struct AttachArgs {
    port: u16,
    #[arg(long)]
    shell: Option<String>,
}

#[derive(clap::Args)]
struct WatchArgs {
    #[arg(short = 'i', long, default_value = "2s", value_parser = parse_duration)]
    interval: Duration,
    #[arg(short = 'a', long)]
    all: bool,
    #[arg(short = 'n', long)]
    notify: bool,
    #[arg(long)]
    stats: bool,
    #[arg(long)]
    host: Option<String>,
}

#[derive(clap::Args)]
struct GraphArgs {
    #[arg(long)]
    json: bool,
    #[arg(long)]
    dot: bool,
}

#[derive(clap::Args)]
struct MapArgs {
    service_port: u16,
    listen_port: u16,
}

#[derive(Subcommand)]
enum ProfileSubcommand {
    List,
    Show(ProfileNameArg),
    Create(ProfileNameArg),
    Delete(ProfileNameArg),
}

#[derive(clap::Args)]
struct ProfileArgs {
    #[command(subcommand)]
    command: ProfileSubcommand,
}

#[derive(clap::Args)]
struct ProfileNameArg {
    name: String,
}

#[derive(clap::Args)]
struct DownArgs {
    name: String,
    #[arg(short = 'y', long)]
    yes: bool,
    #[arg(short = 'f', long)]
    force: bool,
}

#[derive(clap::Args)]
struct VersionArgs {
    #[arg(long)]
    check: bool,
}

#[derive(clap::Args)]
struct CompletionArgs {
    shell: Shell,
}

#[derive(Clone, Copy, Debug)]
struct ContextState {
    no_color: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PortType {
    System,
    #[default]
    User,
    Docker,
}

impl PortType {
    fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Docker => "docker",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ListeningPort {
    port: u16,
    pid: u32,
    process: String,
    command: String,
    user: String,
    bind_address: String,
    ip_version: String,
    #[serde(rename = "type")]
    port_type: PortType,
    is_app: bool,
    cpu_percent: f64,
    memory_rss: u64,
    thread_count: u32,
    start_time: String,
    uptime: String,
    state: String,
    connections: usize,
    health_status: String,
    health_code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    health_latency_ms: Option<u128>,
    docker_container: String,
    docker_image: String,
    docker_compose_service: String,
    docker_compose_project: String,
    docker_container_port: u16,
}

impl ListeningPort {
    fn url(&self) -> String {
        format!("http://localhost:{}", self.port)
    }

    fn display_name(&self) -> String {
        if !self.docker_compose_service.is_empty() {
            return self.docker_compose_service.clone();
        }
        if !self.docker_container.is_empty() {
            return self.docker_container.clone();
        }
        if !self.command.is_empty() {
            return short_command(&self.command);
        }
        self.process.clone()
    }
}

#[derive(Clone, Debug, Serialize)]
struct Connection {
    from_port: u16,
    from_process: String,
    to_port: u16,
    to_process: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DockerInspectEntry {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Config")]
    config: DockerConfig,
    #[serde(rename = "NetworkSettings")]
    network_settings: DockerNetworkSettings,
    #[serde(rename = "State")]
    state: DockerState,
}

#[derive(Clone, Debug, Deserialize)]
struct DockerConfig {
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Labels", default)]
    labels: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
struct DockerNetworkSettings {
    #[serde(rename = "Ports", default)]
    ports: HashMap<String, Option<Vec<DockerPortBinding>>>,
}

#[derive(Clone, Debug, Deserialize)]
struct DockerPortBinding {
    #[serde(rename = "HostPort")]
    host_port: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DockerState {
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "StartedAt")]
    started_at: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DockerStatsLine {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "CPUPerc")]
    cpu_perc: String,
    #[serde(rename = "MemUsage")]
    mem_usage: String,
    #[serde(rename = "PIDs")]
    pids: String,
}

#[derive(Clone, Debug, Default)]
struct DockerStats {
    cpu_percent: f64,
    memory_rss: u64,
    pids: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Profile {
    name: String,
    #[serde(default)]
    description: String,
    ports: Vec<ProfileEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProfileEntry {
    port: u16,
    name: String,
    #[serde(default)]
    health: bool,
    #[serde(default)]
    health_path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PortFilter {
    Docker,
    User,
    System,
}

impl PortFilter {
    fn matches(self, port: &ListeningPort) -> bool {
        match self {
            Self::Docker => port.port_type == PortType::Docker,
            Self::User => port.port_type == PortType::User,
            Self::System => port.port_type == PortType::System,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum SortKey {
    #[default]
    Port,
    Pid,
    Name,
    Type,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Column {
    Port,
    Process,
    Pid,
    Type,
    Url,
    Cpu,
    Mem,
    Threads,
    Uptime,
    State,
    Connections,
    Container,
    Image,
    ContainerPort,
    Compose,
    Project,
    User,
    Bind,
    Ip,
    Health,
    Latency,
}

impl Column {
    fn label(self) -> &'static str {
        match self {
            Self::Port => "PORT",
            Self::Process => "PROCESS",
            Self::Pid => "PID",
            Self::Type => "TYPE",
            Self::Url => "URL",
            Self::Cpu => "CPU%",
            Self::Mem => "MEM",
            Self::Threads => "THR",
            Self::Uptime => "UPTIME",
            Self::State => "STATE",
            Self::Connections => "CONN",
            Self::Container => "CONTAINER",
            Self::Image => "IMAGE",
            Self::ContainerPort => "CPORT",
            Self::Compose => "SERVICE",
            Self::Project => "PROJECT",
            Self::User => "USER",
            Self::Bind => "BIND",
            Self::Ip => "IP",
            Self::Health => "HEALTH",
            Self::Latency => "LATENCY",
        }
    }

    fn value(self, port: &ListeningPort) -> String {
        match self {
            Self::Port => port.port.to_string(),
            Self::Process => port.display_name(),
            Self::Pid => port.pid.to_string(),
            Self::Type => port.port_type.as_str().to_owned(),
            Self::Url => port.url(),
            Self::Cpu => {
                if port.cpu_percent > 0.0 {
                    format!("{:.1}", port.cpu_percent)
                } else {
                    String::new()
                }
            }
            Self::Mem => {
                if port.memory_rss > 0 {
                    format_bytes(port.memory_rss)
                } else {
                    String::new()
                }
            }
            Self::Threads => {
                if port.thread_count > 0 {
                    port.thread_count.to_string()
                } else {
                    String::new()
                }
            }
            Self::Uptime => port.uptime.clone(),
            Self::State => port.state.clone(),
            Self::Connections => port.connections.to_string(),
            Self::Container => port.docker_container.clone(),
            Self::Image => port.docker_image.clone(),
            Self::ContainerPort => {
                if port.docker_container_port > 0 {
                    port.docker_container_port.to_string()
                } else {
                    String::new()
                }
            }
            Self::Compose => port.docker_compose_service.clone(),
            Self::Project => port.docker_compose_project.clone(),
            Self::User => port.user.clone(),
            Self::Bind => port.bind_address.clone(),
            Self::Ip => port.ip_version.clone(),
            Self::Health => port.health_status.clone(),
            Self::Latency => port
                .health_latency_ms
                .map(|value| format!("{value}ms"))
                .unwrap_or_default(),
        }
    }
}

fn list_command(context: &ContextState, args: ListArgs) -> Result<()> {
    let mut ports = if let Some(host) = args.host.as_deref() {
        let mut ports = scan_remote(host)?;
        for port in &mut ports {
            port.port_type = classify_port(port.port);
        }
        ports
    } else {
        let mut ports = scan_local()?;
        enrich_docker(&mut ports);
        enrich_processes(&mut ports)?;
        if args.stats {
            enrich_stats(&mut ports)?;
        }
        if args.health {
            enrich_health(&mut ports, Duration::from_secs(2));
        }
        ports
    };

    if !args.all {
        ports.retain(|port| !port.is_app);
    }
    if let Some(filter) = args.filter {
        ports.retain(|port| filter.matches(port));
    }
    sort_ports(&mut ports, args.sort);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&ports).context("failed to serialize JSON")?
        );
        return Ok(());
    }

    let columns = if args.all_columns {
        ALL_COLUMNS.to_vec()
    } else if !args.columns.is_empty() {
        args.columns
    } else if args.stats {
        vec![
            Column::Port,
            Column::Pid,
            Column::Process,
            Column::Container,
            Column::Image,
            Column::ContainerPort,
            Column::Cpu,
            Column::Mem,
            Column::State,
            Column::Uptime,
            Column::Connections,
            Column::Url,
        ]
    } else {
        DEFAULT_COLUMNS.to_vec()
    };

    render_table(context, &ports, &columns);
    Ok(())
}

fn info_command(args: PortArg) -> Result<()> {
    let port = if let Some(host) = args.host.as_deref() {
        let mut ports = scan_remote(host)?;
        let mut port = find_by_port(&mut ports, args.port).ok_or_else(|| {
            anyhow!(
                "no process found listening on port {} on {}",
                args.port,
                host
            )
        })?;
        port.port_type = classify_port(port.port);
        port
    } else {
        let mut ports = scan_local()?;
        enrich_docker(&mut ports);
        enrich_processes(&mut ports)?;
        enrich_stats(&mut ports)?;
        enrich_health(&mut ports, Duration::from_secs(2));
        find_by_port(&mut ports, args.port)
            .ok_or_else(|| anyhow!("no process found listening on port {}", args.port))?
    };

    print_field("Port", &port.port.to_string());
    print_field("URL", &port.url());
    print_field("Process", &port.process);
    print_field("PID", &port.pid.to_string());
    print_field("Type", port.port_type.as_str());
    if !port.command.is_empty() {
        print_field("Command", &port.command);
    }
    if !port.user.is_empty() {
        print_field("User", &port.user);
    }
    if !port.bind_address.is_empty() {
        print_field("Bind Address", &port.bind_address);
    }
    if !port.ip_version.is_empty() {
        print_field("IP Version", &port.ip_version);
    }

    println!();
    println!("Stats:");
    print_field("  CPU", &format!("{:.1}%", port.cpu_percent));
    if port.memory_rss > 0 {
        print_field("  Memory", &format_bytes(port.memory_rss));
    }
    if port.thread_count > 0 {
        print_field("  Threads", &port.thread_count.to_string());
    }
    if !port.uptime.is_empty() {
        print_field("  Uptime", &port.uptime);
    }
    if !port.state.is_empty() {
        print_field("  State", &port.state);
    }
    print_field("  Connections", &port.connections.to_string());

    println!();
    println!("Health:");
    print_field("  Status", &port.health_status);
    if port.health_code > 0 {
        print_field("  Status Code", &port.health_code.to_string());
    }
    if let Some(latency_ms) = port.health_latency_ms {
        print_field("  Latency", &format!("{latency_ms}ms"));
    }

    if port.port_type == PortType::Docker {
        println!();
        println!("Docker:");
        if !port.docker_container.is_empty() {
            print_field("  Container", &port.docker_container);
        }
        if !port.docker_image.is_empty() {
            print_field("  Image", &port.docker_image);
        }
        if port.docker_container_port > 0 {
            print_field("  Container Port", &port.docker_container_port.to_string());
        }
        if !port.docker_compose_service.is_empty() {
            print_field("  Compose Service", &port.docker_compose_service);
        }
        if !port.docker_compose_project.is_empty() {
            print_field("  Compose Project", &port.docker_compose_project);
        }
    }

    Ok(())
}

fn kill_command(args: KillArgs) -> Result<()> {
    let mut ports = scan_local()?;
    enrich_docker(&mut ports);
    let port = find_by_port(&mut ports, args.port)
        .ok_or_else(|| anyhow!("no process found listening on port {}", args.port))?;

    if port.port_type == PortType::Docker {
        let name = if !port.docker_compose_service.is_empty() {
            port.docker_compose_service.clone()
        } else {
            port.docker_container.clone()
        };
        println!("Stopping Docker container {name} on port {}", args.port);
        stop_container(&port.docker_container)?;
        println!("Freed {}", port.url());
        return Ok(());
    }

    let signal_name = if args.force { "SIGKILL" } else { "SIGTERM" };
    println!(
        "Killing {} (PID {}) on port {} with {}",
        port.display_name(),
        port.pid,
        port.port,
        signal_name
    );
    kill_pid(port.pid, args.force)?;
    println!("Freed {}", port.url());
    Ok(())
}

fn kill_all_command(args: KillAllArgs) -> Result<()> {
    let mut ports = scan_local()?;
    enrich_docker(&mut ports);
    enrich_processes(&mut ports)?;

    if !args.all {
        ports.retain(|port| !port.is_app);
    }
    if let Some(filter) = args.filter {
        ports.retain(|port| filter.matches(port));
    }
    if let Some(project) = args.project.as_deref() {
        ports.retain(|port| port.docker_compose_project.eq_ignore_ascii_case(project));
    }

    if ports.is_empty() {
        println!("No matching ports found.");
        return Ok(());
    }

    println!("Will kill {} process(es):", ports.len());
    for port in &ports {
        println!("  - {} on port {}", port.display_name(), port.port);
    }
    if !args.yes && !confirm()? {
        println!("Aborted.");
        return Ok(());
    }

    let mut errors = Vec::new();
    let mut killed = 0usize;
    for port in ports {
        let result = if port.port_type == PortType::Docker {
            println!(
                "Stopping Docker container {} on port {}",
                port.display_name(),
                port.port
            );
            stop_container(&port.docker_container)
        } else {
            let signal_name = if args.force { "SIGKILL" } else { "SIGTERM" };
            println!(
                "Killing {} (PID {}) on port {} with {}",
                port.display_name(),
                port.pid,
                port.port,
                signal_name
            );
            kill_pid(port.pid, args.force)
        };

        match result {
            Ok(()) => {
                println!("Freed {}", port.url());
                killed += 1;
            }
            Err(error) => errors.push(format!("port {}: {error}", port.port)),
        }
    }

    println!();
    println!("{killed}/{} processes killed.", killed + errors.len());
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("some processes failed to kill:\n  {}", errors.join("\n  "));
    }
}

fn logs_command(args: LogsArgs) -> Result<()> {
    let mut ports = scan_local()?;
    enrich_docker(&mut ports);
    enrich_processes(&mut ports)?;
    let port = find_by_port(&mut ports, args.port)
        .ok_or_else(|| anyhow!("no process found listening on port {}", args.port))?;

    println!("Attaching to {} (PID {})", port.display_name(), port.pid);
    println!();

    if port.port_type == PortType::Docker && !port.docker_container.is_empty() {
        let mut command = Command::new("docker");
        command.arg("logs");
        if args.follow {
            command.arg("-f");
        }
        command.arg(&port.docker_container);
        return exec_replace(command);
    }

    let sources = find_log_sources(port.pid)?;
    if !sources.is_empty() {
        for source in &sources {
            println!("  {}", source);
        }
        println!();
        let mut command = Command::new("tail");
        if args.follow {
            command.arg("-f");
        }
        for source in sources {
            command.arg(source);
        }
        return exec_replace(command);
    }

    if cfg!(target_os = "macos") {
        println!("No log files found, falling back to system log stream...");
        println!();
        let mut command = Command::new("log");
        command
            .arg("stream")
            .arg("--process")
            .arg(port.pid.to_string())
            .arg("--style")
            .arg("compact");
        return exec_replace(command);
    }

    let proc_paths = [
        format!("/proc/{}/fd/1", port.pid),
        format!("/proc/{}/fd/2", port.pid),
    ];
    let existing: Vec<_> = proc_paths
        .into_iter()
        .filter(|path| Path::new(path).exists())
        .collect();
    if existing.is_empty() {
        bail!("no log sources found for PID {}", port.pid);
    }
    let mut command = Command::new("tail");
    if args.follow {
        command.arg("-f");
    }
    for path in existing {
        command.arg(path);
    }
    exec_replace(command)
}

fn attach_command(args: AttachArgs) -> Result<()> {
    let mut ports = scan_local()?;
    enrich_docker(&mut ports);
    enrich_processes(&mut ports)?;
    let port = find_by_port(&mut ports, args.port)
        .ok_or_else(|| anyhow!("no process found listening on port {}", args.port))?;

    if port.port_type == PortType::Docker && !port.docker_container.is_empty() {
        let shell = args
            .shell
            .unwrap_or_else(|| detect_container_shell(&port.docker_container));
        println!(
            "Attaching shell to container {} ({})",
            port.docker_container, shell
        );
        let mut command = Command::new("docker");
        command
            .arg("exec")
            .arg("-it")
            .arg(&port.docker_container)
            .arg(shell);
        return exec_replace(command);
    }

    println!("Connecting to localhost:{}", port.port);
    let client = if command_exists("ncat") {
        "ncat"
    } else if command_exists("nc") {
        "nc"
    } else {
        bail!("no TCP client found (install ncat or nc)");
    };

    let mut command = Command::new(client);
    command.arg("localhost").arg(port.port.to_string());
    exec_replace(command)
}

fn open_command(args: PortArg) -> Result<()> {
    let url = format!("http://localhost:{}", args.port);
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "linux") {
        "xdg-open"
    } else {
        bail!("unsupported platform");
    };
    println!("Opening {url}");
    Command::new(opener)
        .arg(url)
        .spawn()
        .context("failed to launch browser")?;
    Ok(())
}

fn watch_command(context: &ContextState, args: WatchArgs) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    {
        let running = Arc::clone(&running);
        ctrlc::set_handler(move || running.store(false, Ordering::SeqCst))
            .context("failed to install signal handler")?;
    }

    let stats_columns = vec![
        Column::Port,
        Column::Pid,
        Column::Process,
        Column::Container,
        Column::Image,
        Column::ContainerPort,
        Column::Cpu,
        Column::Mem,
        Column::State,
        Column::Uptime,
        Column::Connections,
        Column::Url,
    ];

    let mut current = scan_for_watch(&args)?;
    if !args.all {
        current.retain(|port| !port.is_app);
    }

    if args.stats {
        print!("\x1b[?25l");
        io::stdout().flush().ok();
        render_live_table(context, &current, &stats_columns, true);
    } else {
        render_table(context, &current, DEFAULT_COLUMNS);
        println!();
        println!("Watching for changes... (Ctrl+C to stop)");
        println!();
    }

    while running.load(Ordering::SeqCst) {
        thread::sleep(args.interval);
        let mut next = match scan_for_watch(&args) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if !args.all {
            next.retain(|port| !port.is_app);
        }
        if args.stats {
            render_live_table(context, &next, &stats_columns, false);
        } else {
            print_diff(args.notify, &current, &next);
        }
        current = next;
    }

    if args.stats {
        print!("\x1b[?25h\n");
        io::stdout().flush().ok();
    }
    Ok(())
}

fn graph_command(args: GraphArgs) -> Result<()> {
    let mut ports = scan_local()?;
    enrich_docker(&mut ports);
    enrich_processes(&mut ports)?;
    let connections = build_graph(&ports)?;

    if connections.is_empty() {
        println!("No inter-service connections detected.");
        return Ok(());
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&connections).context("failed to serialize JSON")?
        );
        return Ok(());
    }
    if args.dot {
        println!("digraph sonar {{");
        println!("  rankdir=LR;");
        println!("  node [shape=box, style=rounded];");
        let mut nodes = BTreeSet::new();
        for connection in &connections {
            nodes.insert(format!(
                "{}:{}",
                connection.from_process, connection.from_port
            ));
            nodes.insert(format!("{}:{}", connection.to_process, connection.to_port));
        }
        for node in nodes {
            println!("  {node:?};");
        }
        println!();
        for connection in &connections {
            let from = format!("{}:{}", connection.from_process, connection.from_port);
            let to = format!("{}:{}", connection.to_process, connection.to_port);
            println!("  {from:?} -> {to:?};");
        }
        println!("}}");
        return Ok(());
    }

    for connection in connections {
        println!(
            "{} ({}) -> {} ({})",
            connection.from_process,
            connection.from_port,
            connection.to_process,
            connection.to_port
        );
    }
    Ok(())
}

fn map_command(args: MapArgs) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", args.listen_port))
        .with_context(|| format!("failed to listen on port {}", args.listen_port))?;
    println!(
        "http://localhost:{} -> http://localhost:{}",
        args.listen_port, args.service_port
    );
    println!("Press Ctrl+C to stop");

    for stream in listener.incoming() {
        let Ok(source) = stream else { break };
        let target_port = args.service_port;
        let listen_port = args.listen_port;
        thread::spawn(move || {
            if let Err(error) = proxy_connection(source, target_port) {
                eprintln!("proxy error on {listen_port}: {error}");
            }
        });
    }

    Ok(())
}

fn profile_command(args: ProfileArgs) -> Result<()> {
    match args.command {
        ProfileSubcommand::List => {
            let names = list_profiles()?;
            if names.is_empty() {
                println!("No profiles found.");
                println!("Create one with: sonar profile create <name>");
                return Ok(());
            }
            println!("Saved profiles:");
            for name in names {
                println!("  - {name}");
            }
            Ok(())
        }
        ProfileSubcommand::Show(arg) => {
            let profile = load_profile(&arg.name)?;
            println!("{}", profile.name);
            if !profile.description.is_empty() {
                println!("  {}", profile.description);
            }
            println!();
            println!("  PORT     NAME                 HEALTH");
            for entry in profile.ports {
                let health = if entry.health {
                    if entry.health_path.is_empty() {
                        "yes".to_owned()
                    } else {
                        entry.health_path
                    }
                } else {
                    "no".to_owned()
                };
                println!("  {:<8} {:<20} {}", entry.port, entry.name, health);
            }
            Ok(())
        }
        ProfileSubcommand::Create(arg) => {
            let mut ports = scan_local()?;
            enrich_docker(&mut ports);
            enrich_processes(&mut ports)?;
            ports.retain(|port| !port.is_app);
            if ports.is_empty() {
                bail!("no listening ports found to snapshot");
            }

            let profile = Profile {
                name: arg.name,
                description: String::new(),
                ports: ports
                    .into_iter()
                    .map(|port| ProfileEntry {
                        port: port.port,
                        name: port.display_name(),
                        health: false,
                        health_path: String::new(),
                    })
                    .collect(),
            };
            save_profile(&profile)?;
            println!(
                "Profile {} created with {} port(s).",
                profile.name,
                profile.ports.len()
            );
            for entry in profile.ports {
                println!("  {}  {}", entry.port, entry.name);
            }
            Ok(())
        }
        ProfileSubcommand::Delete(arg) => {
            delete_profile(&arg.name)?;
            println!("Profile {} deleted.", arg.name);
            Ok(())
        }
    }
}

fn up_command(args: ProfileNameArg) -> Result<()> {
    let profile = load_profile(&args.name)?;
    let mut ports = scan_local()?;
    enrich_docker(&mut ports);
    enrich_processes(&mut ports)?;

    let mut port_map = HashMap::new();
    for port in ports {
        port_map.insert(port.port, port);
    }

    println!();
    println!("  {}  profile status", profile.name);
    println!();
    println!("  PORT     NAME               STATUS         HEALTH");

    let mut all_up = true;
    for entry in profile.ports {
        if let Some(port) = port_map.get(&entry.port) {
            let mut health = "non-http".to_owned();
            if entry.health {
                let mut only = vec![port.clone()];
                enrich_health(&mut only, Duration::from_secs(2));
                health = only[0].health_status.clone();
            }
            println!(
                "  {:<8} {:<18} {:<14} {}",
                entry.port, entry.name, "up", health
            );
        } else {
            all_up = false;
            println!(
                "  {:<8} {:<18} {:<14} {}",
                entry.port, entry.name, "missing", "-"
            );
        }
    }

    println!();
    if all_up {
        println!("  All ports are up.");
    } else {
        println!("  Some ports are missing.");
    }
    println!();
    Ok(())
}

fn down_command(args: DownArgs) -> Result<()> {
    let profile = load_profile(&args.name)?;
    let mut ports = scan_local()?;
    enrich_docker(&mut ports);
    enrich_processes(&mut ports)?;

    let port_map: HashMap<_, _> = ports.into_iter().map(|port| (port.port, port)).collect();
    let active: Vec<_> = profile
        .ports
        .iter()
        .filter_map(|entry| port_map.get(&entry.port).cloned())
        .collect();

    if active.is_empty() {
        println!("No profile ports are currently running.");
        return Ok(());
    }

    println!(
        "Will stop {} process(es) from profile {}:",
        active.len(),
        profile.name
    );
    for port in &active {
        println!("  - {} on port {}", port.display_name(), port.port);
    }
    if !args.yes && !confirm()? {
        println!("Aborted.");
        return Ok(());
    }

    let mut errors = Vec::new();
    let mut stopped = 0usize;
    for port in active {
        let result = if port.port_type == PortType::Docker {
            stop_container(&port.docker_container)
        } else {
            kill_pid(port.pid, args.force)
        };
        match result {
            Ok(()) => {
                println!("Freed {}", port.url());
                stopped += 1;
            }
            Err(error) => errors.push(format!("port {}: {error}", port.port)),
        }
    }
    println!();
    println!("{stopped}/{} processes stopped.", stopped + errors.len());
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("some processes failed to stop:\n  {}", errors.join("\n  "));
    }
}

fn version_command(args: VersionArgs) -> Result<()> {
    println!("{}", env!("CARGO_PKG_VERSION"));
    if args.check {
        let release: GithubRelease = reqwest::blocking::Client::new()
            .get("https://api.github.com/repos/RasKrebs/sonar/releases/latest")
            .header("User-Agent", "sonar-rust")
            .send()
            .context("failed to check latest release")?
            .error_for_status()
            .context("release check failed")?
            .json()
            .context("failed to parse release response")?;
        if release.tag_name.trim_start_matches('v') > env!("CARGO_PKG_VERSION") {
            println!("A newer version is available: {}", release.tag_name);
        } else {
            println!("You are running the latest version");
        }
    }
    Ok(())
}

fn completion_command(args: CompletionArgs) -> Result<()> {
    let mut command = Cli::command();
    let mut stdout = io::stdout();
    generate_completion(args.shell, &mut command, "sonar", &mut stdout);
    Ok(())
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
}

fn generate_completion<G: Generator>(
    generator: G,
    command: &mut clap::Command,
    bin_name: &str,
    buffer: &mut dyn Write,
) {
    generate(generator, command, bin_name, buffer);
}

fn scan_for_watch(args: &WatchArgs) -> Result<Vec<ListeningPort>> {
    if let Some(host) = args.host.as_deref() {
        let mut ports = scan_remote(host)?;
        for port in &mut ports {
            port.port_type = classify_port(port.port);
        }
        return Ok(ports);
    }
    let mut ports = scan_local()?;
    enrich_docker(&mut ports);
    enrich_processes(&mut ports)?;
    if args.stats {
        enrich_stats(&mut ports)?;
    }
    Ok(ports)
}

fn scan_local() -> Result<Vec<ListeningPort>> {
    if cfg!(target_os = "macos") {
        let output =
            command_output(Command::new("lsof").args(["-iTCP", "-sTCP:LISTEN", "-n", "-P"]))?;
        Ok(parse_lsof(&output))
    } else if cfg!(target_os = "linux") {
        let output = command_output(Command::new("ss").args(["-tlnp"]))?;
        Ok(parse_ss(&output))
    } else {
        bail!("unsupported platform");
    }
}

fn scan_remote(host: &str) -> Result<Vec<ListeningPort>> {
    let output = command_output(
        Command::new("ssh")
            .arg(host)
            .arg("ss -tlnp 2>/dev/null || lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null"),
    )?;
    let first_line = output.lines().next().unwrap_or_default();
    if first_line.starts_with("COMMAND") {
        Ok(parse_lsof(&output))
    } else {
        Ok(parse_ss(&output))
    }
}

fn parse_lsof(output: &str) -> Vec<ListeningPort> {
    let mut seen = HashSet::new();
    let mut ports = Vec::new();

    for line in output.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 9 {
            continue;
        }

        let Some(pid) = fields[1].parse::<u32>().ok() else {
            continue;
        };
        let Some(port_number) = parse_port_number(fields[8]) else {
            continue;
        };
        if !seen.insert(port_number) {
            continue;
        }

        let bind_address = parse_bind_address(fields[8]).unwrap_or_default();
        let ip_version = if fields[4] == "IPv6" { "IPv6" } else { "IPv4" };

        ports.push(ListeningPort {
            port: port_number,
            pid,
            process: fields[0].to_owned(),
            user: fields[2].to_owned(),
            bind_address,
            ip_version: ip_version.to_owned(),
            ..ListeningPort::default()
        });
    }

    ports
}

fn parse_ss(output: &str) -> Vec<ListeningPort> {
    let mut seen = HashSet::new();
    let mut ports = Vec::new();

    for line in output.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }

        let local = fields[3];
        let Some(port_number) = parse_port_number(local) else {
            continue;
        };
        if !seen.insert(port_number) {
            continue;
        }

        let bind_address = parse_bind_address(local).unwrap_or_default();
        let ip_version = if bind_address.contains('[') || bind_address.contains("::") {
            "IPv6"
        } else {
            "IPv4"
        };

        let users_fragment = fields.iter().find(|field| field.starts_with("users:"));
        let pid = users_fragment
            .and_then(|field| extract_numeric_after(field, "pid="))
            .unwrap_or(0);
        let process = users_fragment
            .and_then(|field| extract_quoted_process(field))
            .unwrap_or_default();

        ports.push(ListeningPort {
            port: port_number,
            pid,
            process,
            bind_address,
            ip_version: ip_version.to_owned(),
            ..ListeningPort::default()
        });
    }

    ports
}

fn enrich_processes(ports: &mut [ListeningPort]) -> Result<()> {
    let pid_list = unique_pids(ports);
    if pid_list.is_empty() {
        return Ok(());
    }

    let pid_arg = join_u32(&pid_list);
    let output = Command::new("ps")
        .args(["-o", "pid=,command=", "-p", &pid_arg])
        .output()
        .context("failed to fetch process commands")?;
    if output.status.success() {
        let mut commands = HashMap::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.split_whitespace();
            let Some(pid_text) = parts.next() else {
                continue;
            };
            let Some(pid) = pid_text.parse::<u32>().ok() else {
                continue;
            };
            let command = trimmed
                .strip_prefix(pid_text)
                .map(str::trim)
                .unwrap_or_default()
                .to_owned();
            commands.insert(pid, command);
        }

        for port in ports.iter_mut() {
            if let Some(command) = commands.get(&port.pid) {
                port.command = command.trim().to_owned();
            }
        }
    }

    for port in ports {
        if port.port_type != PortType::Docker {
            port.port_type = classify_port(port.port);
            port.is_app = is_desktop_app(&port.command);
        }
    }
    Ok(())
}

fn enrich_stats(ports: &mut [ListeningPort]) -> Result<()> {
    let docker_stats = docker_stats_map();
    for port in ports
        .iter_mut()
        .filter(|port| port.port_type == PortType::Docker)
    {
        if let Some(stats) = docker_stats.get(&port.docker_container) {
            port.cpu_percent = stats.cpu_percent;
            port.memory_rss = stats.memory_rss;
            port.thread_count = stats.pids;
            if port.state.is_empty() {
                port.state = "running".to_owned();
            }
        }
    }

    let native_pids: Vec<_> = ports
        .iter()
        .filter(|port| port.port_type != PortType::Docker && port.pid > 0)
        .map(|port| port.pid)
        .collect();
    if !native_pids.is_empty() {
        let pid_arg = join_u32(&native_pids);
        let format = if cfg!(target_os = "macos") {
            "pid=,%cpu=,rss=,state=,lstart="
        } else {
            "pid=,%cpu=,rss=,nlwp=,state=,lstart="
        };
        let output = command_output(Command::new("ps").args(["-o", format, "-p", &pid_arg]))?;
        let mut by_pid: HashMap<u32, usize> = HashMap::new();
        for (index, port) in ports.iter().enumerate() {
            by_pid.insert(port.pid, index);
        }
        for line in output.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 2 {
                continue;
            }
            let Some(pid) = fields[0].parse::<u32>().ok() else {
                continue;
            };
            let Some(index) = by_pid.get(&pid).copied() else {
                continue;
            };
            if cfg!(target_os = "macos") {
                parse_darwin_stats(&mut ports[index], &fields[1..]);
                ports[index].thread_count = count_threads_darwin(pid).unwrap_or(1);
            } else {
                parse_linux_stats(&mut ports[index], &fields[1..]);
            }
        }
    }

    for port in ports.iter_mut() {
        port.connections = count_connections(port.port).unwrap_or(0);
    }
    Ok(())
}

fn enrich_health(ports: &mut [ListeningPort], timeout: Duration) {
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build();
    let Ok(client) = client else { return };

    for port in ports {
        let start = Instant::now();
        let response = client.get(port.url()).send();
        let latency = start.elapsed();
        port.health_latency_ms = Some(latency.as_millis());
        match response {
            Ok(response) => {
                port.health_code = response.status().as_u16();
                port.health_status =
                    if response.status().is_success() || response.status().is_redirection() {
                        "healthy".to_owned()
                    } else {
                        "unhealthy".to_owned()
                    };
            }
            Err(error) => {
                if error.is_timeout() {
                    port.health_status = "timeout".to_owned();
                } else if error.is_connect() {
                    port.health_status = "refused".to_owned();
                } else {
                    port.health_status = "non-http".to_owned();
                }
            }
        }
    }
}

fn enrich_docker(ports: &mut [ListeningPort]) {
    let Ok(containers) = list_docker_containers() else {
        return;
    };
    let mut mapping = HashMap::new();
    for container in containers {
        for (host_port, container_port) in container.host_port_mappings() {
            mapping.insert(host_port, (container.clone(), container_port));
        }
    }

    for port in ports {
        if let Some((container, container_port)) = mapping.get(&port.port) {
            port.port_type = PortType::Docker;
            port.docker_container = container.short_name();
            port.docker_image = container.config.image.clone();
            port.docker_compose_service = container
                .config
                .labels
                .get("com.docker.compose.service")
                .cloned()
                .unwrap_or_default();
            port.docker_compose_project = container
                .config
                .labels
                .get("com.docker.compose.project")
                .cloned()
                .unwrap_or_default();
            port.docker_container_port = *container_port;
            port.state = container.state.status.clone();
            port.uptime =
                docker_started_at_to_uptime(&container.state.started_at).unwrap_or_default();
        }
    }
}

impl DockerInspectEntry {
    fn short_name(&self) -> String {
        self.name.trim_start_matches('/').to_owned()
    }

    fn host_port_mappings(&self) -> Vec<(u16, u16)> {
        let mut mappings = Vec::new();
        for (container_port_key, bindings) in &self.network_settings.ports {
            let container_port = container_port_key
                .split('/')
                .next()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(0);
            let Some(bindings) = bindings.as_ref() else {
                continue;
            };
            for binding in bindings {
                if let Ok(host_port) = binding.host_port.parse::<u16>() {
                    mappings.push((host_port, container_port));
                }
            }
        }
        mappings
    }
}

fn list_docker_containers() -> Result<Vec<DockerInspectEntry>> {
    if !command_exists("docker") {
        bail!("docker not installed");
    }

    let ids_output = command_output(Command::new("docker").args(["ps", "-q"]))?;
    let ids: Vec<_> = ids_output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut command = Command::new("docker");
    command.arg("inspect");
    for id in &ids {
        command.arg(id);
    }
    let inspect_output = command_output(&mut command)?;
    let containers: Vec<DockerInspectEntry> =
        serde_json::from_str(&inspect_output).context("failed to parse docker inspect JSON")?;
    Ok(containers)
}

fn docker_stats_map() -> HashMap<String, DockerStats> {
    let Ok(output) = command_output(Command::new("docker").args([
        "stats",
        "--no-stream",
        "--format",
        "{{json .}}",
    ])) else {
        return HashMap::new();
    };

    let mut result = HashMap::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let Ok(stats) = serde_json::from_str::<DockerStatsLine>(line) else {
            continue;
        };
        result.insert(
            stats.name.clone(),
            DockerStats {
                cpu_percent: parse_percent(&stats.cpu_perc),
                memory_rss: parse_mem_usage(&stats.mem_usage),
                pids: stats.pids.trim().parse::<u32>().unwrap_or(0),
            },
        );
    }
    result
}

fn build_graph(ports: &[ListeningPort]) -> Result<Vec<Connection>> {
    if cfg!(target_os = "macos") {
        build_graph_lsof(ports)
    } else if cfg!(target_os = "linux") {
        build_graph_ss(ports)
    } else {
        bail!("unsupported platform");
    }
}

fn build_graph_lsof(ports: &[ListeningPort]) -> Result<Vec<Connection>> {
    let port_to_name: HashMap<_, _> = ports
        .iter()
        .map(|port| (port.port, port.display_name()))
        .collect();
    let pid_to_port: HashMap<_, _> = ports.iter().map(|port| (port.pid, port.port)).collect();
    let output = command_output(Command::new("lsof").args(["-i", "-n", "-P"]))?;
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for line in output.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 10 || fields[9] != "(ESTABLISHED)" {
            continue;
        }
        let Some(pid) = fields[1].parse::<u32>().ok() else {
            continue;
        };
        let Some(from_port) = pid_to_port.get(&pid).copied() else {
            continue;
        };
        let Some(remote) = fields[8].split("->").nth(1) else {
            continue;
        };
        let Some(to_port) = parse_port_number(remote) else {
            continue;
        };
        if to_port == from_port
            || !port_to_name.contains_key(&to_port)
            || !seen.insert((from_port, to_port))
        {
            continue;
        }
        result.push(Connection {
            from_port,
            from_process: port_to_name.get(&from_port).cloned().unwrap_or_default(),
            to_port,
            to_process: port_to_name.get(&to_port).cloned().unwrap_or_default(),
        });
    }

    Ok(result)
}

fn build_graph_ss(ports: &[ListeningPort]) -> Result<Vec<Connection>> {
    let port_to_name: HashMap<_, _> = ports
        .iter()
        .map(|port| (port.port, port.display_name()))
        .collect();
    let pid_to_port: HashMap<_, _> = ports.iter().map(|port| (port.pid, port.port)).collect();
    let output = command_output(Command::new("ss").args(["-tnp"]))?;
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for line in output.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 5 || fields[0] != "ESTAB" {
            continue;
        }
        let Some(users_fragment) = fields.iter().find(|field| field.starts_with("users:")) else {
            continue;
        };
        let Some(pid) = extract_numeric_after(users_fragment, "pid=") else {
            continue;
        };
        let Some(from_port) = pid_to_port.get(&pid).copied() else {
            continue;
        };
        let Some(to_port) = parse_port_number(fields[4]) else {
            continue;
        };
        if to_port == from_port
            || !port_to_name.contains_key(&to_port)
            || !seen.insert((from_port, to_port))
        {
            continue;
        }
        result.push(Connection {
            from_port,
            from_process: port_to_name.get(&from_port).cloned().unwrap_or_default(),
            to_port,
            to_process: port_to_name.get(&to_port).cloned().unwrap_or_default(),
        });
    }

    Ok(result)
}

fn render_table(_context: &ContextState, ports: &[ListeningPort], columns: &[Column]) {
    let _ = _context.no_color;
    if ports.is_empty() {
        println!("No listening ports found.");
        return;
    }

    let headers: Vec<_> = columns
        .iter()
        .map(|column| column.label().to_owned())
        .collect();
    let rows: Vec<Vec<String>> = ports
        .iter()
        .map(|port| columns.iter().map(|column| column.value(port)).collect())
        .collect();

    let mut widths = headers
        .iter()
        .map(|header| header.len())
        .collect::<Vec<_>>();
    for row in &rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.len());
        }
    }

    for (index, header) in headers.iter().enumerate() {
        if index > 0 {
            print!("   ");
        }
        print!("{header:width$}", width = widths[index]);
    }
    println!();

    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if index > 0 {
                print!("   ");
            }
            print!("{cell:width$}", width = widths[index]);
        }
        println!();
    }

    let docker_count = ports
        .iter()
        .filter(|port| port.port_type == PortType::Docker)
        .count();
    let user_count = ports
        .iter()
        .filter(|port| port.port_type == PortType::User)
        .count();
    let system_count = ports
        .iter()
        .filter(|port| port.port_type == PortType::System)
        .count();
    let mut parts = Vec::new();
    if docker_count > 0 {
        parts.push(format!("{docker_count} docker"));
    }
    if user_count > 0 {
        parts.push(format!("{user_count} user"));
    }
    if system_count > 0 {
        parts.push(format!("{system_count} system"));
    }
    println!();
    if parts.is_empty() {
        println!("{} ports", ports.len());
    } else {
        println!("{} ports ({})", ports.len(), parts.join(", "));
    }
}

fn render_live_table(
    context: &ContextState,
    ports: &[ListeningPort],
    columns: &[Column],
    first_render: bool,
) {
    if !first_render {
        print!("\x1b[H\x1b[2J");
    }
    render_table(context, ports, columns);
    println!();
    println!(
        "Live stats  {}  Ctrl+C to stop",
        unix_now().unwrap_or_default()
    );
    io::stdout().flush().ok();
}

fn print_diff(notify: bool, old: &[ListeningPort], new: &[ListeningPort]) {
    let old_map: HashMap<_, _> = old.iter().map(|port| (port.port, port)).collect();
    let new_map: HashMap<_, _> = new.iter().map(|port| (port.port, port)).collect();
    let timestamp = unix_now().unwrap_or_default();

    for port in new {
        if !old_map.contains_key(&port.port) {
            println!(
                "[{timestamp}] + {:<5} {:<6} {:<20} {}",
                port.port,
                port.pid,
                port.display_name(),
                port.url()
            );
            if notify {
                send_notification(
                    "Port Opened",
                    &format!("Port {} opened ({})", port.port, port.display_name()),
                );
            }
        }
    }
    for port in old {
        if !new_map.contains_key(&port.port) {
            println!(
                "[{timestamp}] - {:<5} {:<6} {:<20} {}",
                port.port,
                port.pid,
                port.display_name(),
                port.url()
            );
            if notify {
                send_notification(
                    "Port Closed",
                    &format!("Port {} closed ({})", port.port, port.display_name()),
                );
            }
        }
    }
}

fn proxy_connection(mut source: TcpStream, target_port: u16) -> Result<()> {
    let mut target = TcpStream::connect(("127.0.0.1", target_port))
        .with_context(|| format!("failed to connect to target port {}", target_port))?;
    let mut source_clone = source
        .try_clone()
        .context("failed to clone source socket")?;
    let mut target_clone = target
        .try_clone()
        .context("failed to clone target socket")?;
    let a = thread::spawn(move || io::copy(&mut source_clone, &mut target));
    let b = thread::spawn(move || io::copy(&mut target_clone, &mut source));
    let _ = a.join();
    let _ = b.join();
    Ok(())
}

fn find_log_sources(pid: u32) -> Result<Vec<String>> {
    if !command_exists("lsof") {
        return Ok(Vec::new());
    }
    let output = command_output(Command::new("lsof").args(["-p", &pid.to_string(), "-Fn", "-a"]))?;
    let mut sources = Vec::new();
    let mut seen = HashSet::new();
    let mut current_fd = String::new();

    for line in output.lines() {
        if let Some(rest) = line.strip_prefix('f') {
            current_fd = rest.to_owned();
        } else if let Some(path) = line.strip_prefix('n') {
            if should_tail_path(path, &current_fd) && seen.insert(path.to_owned()) {
                sources.push(path.to_owned());
            }
        }
    }

    Ok(sources)
}

fn should_tail_path(path: &str, fd: &str) -> bool {
    if !path.starts_with('/') || path.starts_with("/dev/") || path.contains("->") {
        return false;
    }
    if fd == "1" || fd == "2" {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".log")
        || lower.ends_with(".out")
        || lower.contains("/log/")
        || lower.contains("/logs/")
}

fn detect_container_shell(container: &str) -> String {
    let status = Command::new("docker")
        .args(["exec", container, "bash", "-c", "exit 0"])
        .status();
    if status.map(|status| status.success()).unwrap_or(false) {
        "/bin/bash".to_owned()
    } else {
        "/bin/sh".to_owned()
    }
}

fn exec_replace(mut command: Command) -> Result<()> {
    Err(command.exec()).context("failed to execute command")
}

fn stop_container(container: &str) -> Result<()> {
    command_status(Command::new("docker").args(["stop", container]))?;
    Ok(())
}

fn kill_pid(pid: u32, force: bool) -> Result<()> {
    let signal = if force { "-KILL" } else { "-TERM" };
    command_status(Command::new("kill").args([signal, &pid.to_string()]))?;
    Ok(())
}

fn find_by_port(ports: &mut [ListeningPort], port: u16) -> Option<ListeningPort> {
    ports.iter().find(|item| item.port == port).cloned()
}

fn classify_port(port: u16) -> PortType {
    if port < 1024 {
        PortType::System
    } else {
        PortType::User
    }
}

fn is_desktop_app(command: &str) -> bool {
    command.contains(".app/")
        || command.starts_with("/System/Library/")
        || command.starts_with("/usr/libexec/")
}

fn short_command(command: &str) -> String {
    if let Some(index) = command.find(".app/") {
        return Path::new(&command[..index])
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| command.to_owned());
    }

    let parts: Vec<_> = command.split_whitespace().collect();
    if parts.is_empty() {
        return command.to_owned();
    }
    let base = Path::new(parts[0])
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| parts[0].to_owned());
    if parts.len() == 1 {
        return base;
    }
    for argument in parts.iter().skip(1) {
        if !argument.starts_with('-') {
            let suffix = Path::new(argument)
                .file_name()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| (*argument).to_owned());
            return format!("{base} {suffix}");
        }
    }
    base
}

fn parse_bind_address(text: &str) -> Option<String> {
    let port_text = parse_port_number(text)?;
    let suffix = format!(":{port_text}");
    let bind = text.trim_end_matches(&suffix);
    Some(if bind == "*" {
        "0.0.0.0".to_owned()
    } else {
        bind.to_owned()
    })
}

fn parse_port_number(text: &str) -> Option<u16> {
    let candidate = text.rsplit(':').next()?;
    let candidate = candidate.trim_end_matches(')');
    candidate.parse::<u16>().ok()
}

fn extract_numeric_after(text: &str, needle: &str) -> Option<u32> {
    let suffix = text.split(needle).nth(1)?;
    let number = suffix
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    number.parse::<u32>().ok()
}

fn extract_quoted_process(text: &str) -> Option<String> {
    let suffix = text.split("((").nth(1)?;
    let start = suffix.find('"')? + 1;
    let rest = &suffix[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

fn parse_darwin_stats(port: &mut ListeningPort, fields: &[&str]) {
    if fields.len() < 8 {
        return;
    }
    port.cpu_percent = fields[0].parse::<f64>().unwrap_or(0.0);
    port.memory_rss = fields[1].parse::<u64>().unwrap_or(0) * 1024;
    port.state = decode_state(fields[2]);
    port.start_time = fields[3..].join(" ");
    port.uptime = compute_uptime(&port.start_time).unwrap_or_default();
}

fn parse_linux_stats(port: &mut ListeningPort, fields: &[&str]) {
    if fields.len() < 9 {
        return;
    }
    port.cpu_percent = fields[0].parse::<f64>().unwrap_or(0.0);
    port.memory_rss = fields[1].parse::<u64>().unwrap_or(0) * 1024;
    port.thread_count = fields[2].parse::<u32>().unwrap_or(0);
    port.state = decode_state(fields[3]);
    port.start_time = fields[4..].join(" ");
    port.uptime = compute_uptime(&port.start_time).unwrap_or_default();
}

fn count_threads_darwin(pid: u32) -> Result<u32> {
    let output = command_output(Command::new("ps").args(["-M", "-p", &pid.to_string()]))?;
    let lines = output.lines().count();
    Ok(lines.saturating_sub(1) as u32)
}

fn count_connections(port: u16) -> Result<usize> {
    if cfg!(target_os = "macos") {
        let output = command_output(Command::new("lsof").args([
            &format!("-iTCP:{port}"),
            "-sTCP:ESTABLISHED",
            "-n",
            "-P",
        ]))?;
        let count = output.lines().count().saturating_sub(1) / 2;
        Ok(count)
    } else {
        let output = command_output(Command::new("ss").args([
            "-tn",
            "state",
            "established",
            &format!("sport = :{port}"),
        ]))?;
        Ok(output.lines().count().saturating_sub(1))
    }
}

fn decode_state(value: &str) -> String {
    match value.chars().next().unwrap_or_default() {
        'R' => "running",
        'S' => "sleeping",
        'D' => "disk sleep",
        'T' => "stopped",
        'Z' => "zombie",
        'I' => "idle",
        'U' => "uninterruptible",
        _ => value,
    }
    .to_owned()
}

fn compute_uptime(start_time: &str) -> Option<String> {
    let parsed = ["%a %b %e %H:%M:%S %Y", "%a %b %d %H:%M:%S %Y"]
        .iter()
        .find_map(|layout| parse_ps_datetime(start_time, layout));
    Some(format_duration(
        SystemTime::now().duration_since(parsed?).ok()?,
    ))
}

fn parse_ps_datetime(value: &str, layout: &str) -> Option<SystemTime> {
    let output = Command::new("python3")
        .args([
            "-c",
            "import datetime,sys; print(int(datetime.datetime.strptime(sys.argv[1], sys.argv[2]).timestamp()))",
            value,
            layout,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let timestamp = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(timestamp))
}

fn format_duration(duration: Duration) -> String {
    if duration < Duration::from_secs(60) {
        return format!("{}s", duration.as_secs());
    }
    if duration < Duration::from_secs(3600) {
        return format!("{}m{}s", duration.as_secs() / 60, duration.as_secs() % 60);
    }
    if duration < Duration::from_secs(86400) {
        return format!(
            "{}h{}m",
            duration.as_secs() / 3600,
            (duration.as_secs() / 60) % 60
        );
    }
    format!(
        "{}d{}h",
        duration.as_secs() / 86400,
        (duration.as_secs() / 3600) % 24
    )
}

fn format_bytes(bytes: u64) -> String {
    match bytes {
        value if value >= 1 << 30 => format!("{:.1}G", value as f64 / (1 << 30) as f64),
        value if value >= 1 << 20 => format!("{:.1}M", value as f64 / (1 << 20) as f64),
        value if value >= 1 << 10 => format!("{:.1}K", value as f64 / (1 << 10) as f64),
        value => format!("{value}B"),
    }
}

fn docker_started_at_to_uptime(value: &str) -> Option<String> {
    let parsed = value.split('.').next()?;
    let timestamp = Command::new("python3")
        .args([
            "-c",
            "import datetime,sys; print(int(datetime.datetime.fromisoformat(sys.argv[1]).timestamp()))",
            parsed.replace('Z', "+00:00").as_str(),
        ])
        .output()
        .ok()?;
    if !timestamp.status.success() {
        return None;
    }
    let unix = String::from_utf8_lossy(&timestamp.stdout)
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(format_duration(
        SystemTime::now()
            .duration_since(UNIX_EPOCH + Duration::from_secs(unix))
            .ok()?,
    ))
}

fn parse_percent(value: &str) -> f64 {
    value
        .trim()
        .trim_end_matches('%')
        .parse::<f64>()
        .unwrap_or(0.0)
}

fn parse_mem_usage(value: &str) -> u64 {
    let usage = value.split('/').next().unwrap_or_default().trim();
    parse_human_size(usage)
}

fn parse_human_size(value: &str) -> u64 {
    let regex =
        Regex::new(r"(?i)^\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?i?b?)?\s*$").expect("valid regex");
    let Some(captures) = regex.captures(value) else {
        return 0;
    };
    let number = captures
        .get(1)
        .and_then(|value| value.as_str().parse::<f64>().ok())
        .unwrap_or(0.0);
    let unit = captures
        .get(2)
        .map(|value| value.as_str().to_ascii_lowercase())
        .unwrap_or_default();
    let multiplier = match unit.as_str() {
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "k" | "kb" | "kib" => 1024.0,
        _ => 1.0,
    };
    (number * multiplier) as u64
}

fn command_output(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("failed to run {:?}", command))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "command {:?} failed: {}{}{}",
            command,
            output.status,
            if stdout.trim().is_empty() { "" } else { "\n" },
            if stdout.trim().is_empty() {
                stderr.into_owned()
            } else if stderr.trim().is_empty() {
                stdout.into_owned()
            } else {
                format!("{stdout}\n{stderr}")
            }
        );
    }
}

fn command_status(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("failed to run {:?}", command))?;
    if status.success() {
        Ok(())
    } else {
        bail!("command {:?} failed with {}", command, status);
    }
}

fn command_exists(name: &str) -> bool {
    Command::new("sh")
        .args(["-lc", &format!("command -v {name} >/dev/null 2>&1")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn unique_pids(ports: &[ListeningPort]) -> Vec<u32> {
    let mut seen = HashSet::new();
    let mut values = Vec::new();
    for port in ports {
        if port.pid > 0 && seen.insert(port.pid) {
            values.push(port.pid);
        }
    }
    values
}

fn join_u32(values: &[u32]) -> String {
    let mut result = String::new();
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            result.push(',');
        }
        let _ = write!(result, "{value}");
    }
    result
}

fn sort_ports(ports: &mut [ListeningPort], sort_key: SortKey) {
    match sort_key {
        SortKey::Port => ports.sort_by_key(|port| port.port),
        SortKey::Pid => ports.sort_by_key(|port| port.pid),
        SortKey::Name => ports.sort_by_cached_key(|port| port.display_name().to_ascii_lowercase()),
        SortKey::Type => ports.sort_by_key(|port| match port.port_type {
            PortType::System => 0,
            PortType::User => 1,
            PortType::Docker => 2,
        }),
    }
}

fn confirm() -> Result<bool> {
    print!("\nProceed? [y/N] ");
    io::stdout().flush().context("failed to flush prompt")?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("failed to read confirmation")?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

fn print_field(label: &str, value: &str) {
    println!("{label:<16} {value}");
}

fn send_notification(title: &str, body: &str) {
    if cfg!(target_os = "macos") {
        let script = format!("display notification {:?} with title {:?}", body, title);
        let _ = Command::new("osascript").arg("-e").arg(script).status();
    } else if cfg!(target_os = "linux") {
        let _ = Command::new("notify-send").arg(title).arg(body).status();
    }
}

fn parse_duration(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    if let Some(value) = text.strip_suffix("ms") {
        let millis = value.parse::<u64>().map_err(|error| error.to_string())?;
        return Ok(Duration::from_millis(millis));
    }
    if let Some(value) = text.strip_suffix('s') {
        let seconds = value.parse::<u64>().map_err(|error| error.to_string())?;
        return Ok(Duration::from_secs(seconds));
    }
    if let Some(value) = text.strip_suffix('m') {
        let minutes = value.parse::<u64>().map_err(|error| error.to_string())?;
        return Ok(Duration::from_secs(minutes * 60));
    }
    Err(format!("invalid duration {text}"))
}

fn unix_now() -> Option<String> {
    let output = Command::new("date").arg("+%H:%M:%S").output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn profile_dir() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .or_else(dirs::home_dir)
        .ok_or_else(|| anyhow!("failed to resolve config directory"))?;
    let path = base.join("sonar").join("profiles");
    fs::create_dir_all(&path).with_context(|| format!("failed to create {}", path.display()))?;
    Ok(path)
}

fn profile_path(name: &str) -> Result<PathBuf> {
    Ok(profile_dir()?.join(format!("{name}.json")))
}

fn list_profiles() -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(profile_dir()?).context("failed to list profiles")? {
        let entry = entry.context("failed to read profile entry")?;
        if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
            if let Some(stem) = entry.path().file_stem().and_then(|stem| stem.to_str()) {
                names.push(stem.to_owned());
            }
        }
    }
    names.sort();
    Ok(names)
}

fn load_profile(name: &str) -> Result<Profile> {
    let path = profile_path(name)?;
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn save_profile(profile: &Profile) -> Result<()> {
    let path = profile_path(&profile.name)?;
    let raw = serde_json::to_string_pretty(profile).context("failed to encode profile")?;
    fs::write(&path, raw).with_context(|| format!("failed to write {}", path.display()))
}

fn delete_profile(name: &str) -> Result<()> {
    let path = profile_path(name)?;
    fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lsof_rows() {
        let output = "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\nnode    1234 user   21u  IPv4 0x1        0t0  TCP *:3000 (LISTEN)\npostgres 42 postgres  8u IPv6 0x2 0t0 TCP 127.0.0.1:5432 (LISTEN)\n";
        let ports = parse_lsof(output);
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, 3000);
        assert_eq!(ports[0].pid, 1234);
        assert_eq!(ports[0].bind_address, "0.0.0.0");
        assert_eq!(ports[1].port, 5432);
    }

    #[test]
    fn parses_ss_rows() {
        let output = "State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\nLISTEN 0      4096   127.0.0.1:5432      0.0.0.0:*    users:((\"postgres\",pid=321,fd=7))\nLISTEN 0      4096   *:3000               *:*          users:((\"node\",pid=123,fd=21))\n";
        let ports = parse_ss(output);
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, 5432);
        assert_eq!(ports[0].pid, 321);
        assert_eq!(ports[1].process, "node");
    }

    #[test]
    fn short_command_prefers_first_non_flag_arg() {
        assert_eq!(
            short_command("/usr/local/bin/node server.js --port=3000"),
            "node server.js"
        );
    }

    #[test]
    fn formats_bytes_readably() {
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(1024 * 1024), "1.0M");
    }

    #[test]
    fn parses_human_sizes() {
        assert_eq!(parse_human_size("12MiB"), 12 * 1024 * 1024);
        assert_eq!(
            parse_human_size("1.5GiB"),
            (1.5 * 1024.0 * 1024.0 * 1024.0) as u64
        );
    }

    #[test]
    fn default_columns_include_pid() {
        assert_eq!(DEFAULT_COLUMNS[1], Column::Pid);
    }
}
