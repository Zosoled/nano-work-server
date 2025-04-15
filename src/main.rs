mod gpu;
mod rpc;

use gpu::Gpu;
use std::process;

#[tokio::main]
async fn main() {
    let args = clap::App::new("Nano work server")
        .version("1.0")
        .author("Lee Bousfield <ljbousfield@gmail.com>")
        .about("Provides a work server for Nano without a full node.")
        .arg(
            clap::Arg::with_name("listen_address")
                .short("l")
                .long("listen-address")
                .value_name("ADDR")
                .default_value("[::1]:7076")
                .help("Specifies the address to listen on."),
        )
        .arg(
            clap::Arg::with_name("cpu_threads")
                .short("c")
                .long("cpu-threads")
                .value_name("THREADS")
                .default_value("0")
                .help("Specifies how many CPU threads to use."),
        )
        .arg(
            clap::Arg::with_name("gpu")
                .short("g")
                .long("gpu")
                .value_name("PLATFORM:DEVICE:THREADS")
                .multiple(true)
                .help("Specifies which GPU(s) to use. THREADS is optional and defaults to 1048576."),
        )
        .arg(
            clap::Arg::with_name("gpu_local_work_size")
                .long("gpu-local-work-size")
                .value_name("N")
                .help("The GPU local work size. Increasing it may increase performance. For advanced users only."),
        )
        .arg(
            clap::Arg::with_name("shuffle")
                .long("shuffle")
                .help("Pick a random request from the queue instead of the oldest. Increases efficiency when using multiple work servers")
        )
        .get_matches();

    let random_mode = args.is_present("shuffle");
    let listen_addr = args
        .value_of("listen_address")
        .unwrap()
        .parse()
        .expect("Failed to parse listen address");
    let cpu_threads: usize = args
        .value_of("cpu_threads")
        .unwrap()
        .parse()
        .expect("Failed to parse CPU threads");
    let gpu_local_work_size = args.value_of("gpu_local_work_size").map(|s| {
        s.parse()
            .expect("Failed to parse GPU local work size option")
    });

    let gpus: Vec<Gpu> = args
        .values_of("gpu")
        .map(|x| x.collect())
        .unwrap_or_else(Vec::new)
        .into_iter()
        .map(|s| {
            let mut parts = s.split(':');
            let platform = parts
                .next()
                .expect("GPU string cannot be blank")
                .parse()
                .expect(&format!("Failed to parse GPU platform in string {:?}", s));
            let device = parts
                .next()
                .expect(&format!("GPU string {:?} must have at least one colon", s))
                .parse()
                .expect(&format!("Failed to parse GPU device in string {:?}", s));
            let threads = parts
                .next()
                .unwrap_or("1048576")
                .parse()
                .expect(&format!("Failed to parse GPU threads in string {:?}", s));
            if parts.next().is_some() {
                panic!("Too many colons in GPU string {:?}", s);
            }
            Gpu::new(platform, device, threads, gpu_local_work_size)
                .expect(&format!("Failed to create GPU from string {:?}", s))
        })
        .collect();

    let n_workers = gpus.len() + cpu_threads;
    if n_workers == 0 {
        eprintln!("No workers specified. Please use the --gpu or --cpu-threads flags.\nUse --help for more options.");
        process::exit(1);
    }

    rpc::start_server(listen_addr, gpus, cpu_threads, n_workers, random_mode).await;
}
