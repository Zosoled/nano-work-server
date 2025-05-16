use crate::gpu::Gpu;

use chrono::Utc;
use futures::{channel::oneshot, future::ready, Future, TryFutureExt};
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use parking_lot::{Condvar, Mutex};
use rand::{thread_rng, Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use serde_json::{json, Value};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Instant,
};

/// Nano mainnet threshold for send and change blocks.
const LIVE_DIFFICULTY: u64 = 0xfffffff800000000;
/// Nano mainnet threshold for receive, open, and epoch blocks.
const LIVE_RECEIVE_DIFFICULTY: u64 = 0xfffffe0000000000;

#[derive(Debug)]
enum WorkError {
    Canceled,
    Errored,
}

#[derive(Default)]
struct WorkState {
    root: [u8; 32],
    difficulty: u64,
    callback: Option<oneshot::Sender<Result<[u8; 8], WorkError>>>,
    task_working: Arc<AtomicBool>,
    unsuccessful_workers: usize,
    random_mode: bool,
    future_work: Vec<([u8; 32], u64, oneshot::Sender<Result<[u8; 8], WorkError>>)>,
}

impl WorkState {
    fn set_task(&mut self, cond_var: &Condvar) {
        if self.callback.is_none() {
            self.task_working.store(false, Ordering::Relaxed);
            if !self.future_work.is_empty() {
                let i: usize = if self.random_mode {
                    thread_rng().gen_range(0..self.future_work.len())
                } else {
                    0
                };
                let (root, difficulty, callback) = self.future_work.remove(i);
                self.root = root;
                self.difficulty = difficulty;
                self.callback = Some(callback);
                self.task_working = Arc::new(AtomicBool::new(true));
                cond_var.notify_all();
            }
        }
    }
}

/// Compute the PoW value for a given root and work nonce
fn work_value(root: [u8; 32], work: [u8; 8]) -> u64 {
    use blake2::Blake2bVar;
    use byteorder::{ByteOrder, LittleEndian};
    use digest::{Update, VariableOutput};
    let mut buf = [0u8; 8];
    let mut hasher = Blake2bVar::new(buf.len()).expect("Unsupported hash length");
    hasher.update(&work);
    hasher.update(&root);
    hasher.finalize_variable(&mut buf).unwrap();
    LittleEndian::read_u64(&buf)
}

#[inline]
fn work_valid(root: [u8; 32], work: [u8; 8], difficulty: u64) -> (bool, u64) {
    let work_difficulty = work_value(root, work);
    (work_difficulty >= difficulty, work_difficulty)
}

enum RpcCommand {
    WorkGenerate([u8; 32], Option<u64>, Option<f64>),
    WorkCancel([u8; 32]),
    WorkValidate([u8; 32], [u8; 8], Option<u64>, Option<f64>),
    Benchmark(Option<u64>, Option<f64>, u64),
    Status(),
}

#[derive(Debug)]
enum HexJsonError {
    Empty,
    InvalidHex,
    TooLong,
    TooShort,
}

#[derive(Clone)]
struct RpcService {
    work_state: Arc<(Mutex<WorkState>, Condvar)>,
}

impl RpcService {
    fn generate_work(
        &self,
        root: [u8; 32],
        difficulty: u64,
    ) -> impl Future<Output = Result<[u8; 8], WorkError>> {
        let mut state = self.work_state.0.lock();
        let (callback_send, callback_recv) = oneshot::channel();
        state.future_work.push((root, difficulty, callback_send));
        state.set_task(&self.work_state.1);
        callback_recv
            .map_err(|_| WorkError::Errored)
            .and_then(|x| ready(x))
    }

    fn cancel_work(&self, root: [u8; 32]) {
        let mut state = self.work_state.0.lock();
        let mut i = 0;
        while i < state.future_work.len() {
            if state.future_work[i].0 == root {
                let (_, _, callback) = state.future_work.remove(i);
                let _ = callback.send(Err(WorkError::Canceled));
                continue;
            }
            i += 1;
        }
        if state.root == root {
            if let Some(callback) = state.callback.take() {
                let _ = callback.send(Err(WorkError::Canceled));
                state.set_task(&self.work_state.1);
            }
        }
    }

    fn to_multiplier(&self, difficulty: u64) -> f64 {
        (LIVE_DIFFICULTY.wrapping_neg() as f64) / (difficulty.wrapping_neg() as f64)
    }

    fn from_multiplier(&self, multiplier: f64) -> u64 {
        (((LIVE_DIFFICULTY.wrapping_neg() as f64) / multiplier) as u64).wrapping_neg()
    }

    fn parse_hex_json(
        value: &Value,
        out: &mut [u8],
        allow_short: bool,
    ) -> Result<(), HexJsonError> {
        let bytes = value
            .as_str()
            .and_then(|s| hex::decode(s).ok())
            .ok_or(HexJsonError::InvalidHex)?;
        if bytes.is_empty() {
            return Err(HexJsonError::Empty);
        } else if !allow_short && bytes.len() < out.len() {
            return Err(HexJsonError::TooShort);
        } else if bytes.len() > out.len() {
            return Err(HexJsonError::TooLong);
        }
        for (byte, out) in bytes.iter().rev().zip(out.iter_mut().rev()) {
            *out = *byte;
        }
        Ok(())
    }

    fn parse_hash_json(json: &Value) -> Result<[u8; 32], Value> {
        let root = json.get("hash").ok_or(json!({
            "error": "Failed to deserialize JSON",
            "hint": "Hash field missing",
        }))?;
        let mut out = [0u8; 32];
        Self::parse_hex_json(&root, &mut out, false).map_err(|err| match err {
            HexJsonError::Empty => json!({
                "error": "Bad block hash",
                "hint": "Hash is empty. Expecting a hex string",
            }),
            HexJsonError::InvalidHex => json!({
                "error": "Bad block hash",
                "hint": "Expecting a hex string",
            }),
            HexJsonError::TooShort => json!({
                "error": "Bad block hash",
                "hint": "Hash is too short (should be 32 bytes)",
            }),
            HexJsonError::TooLong => json!({
                "error": "Bad block hash",
                "hint": "Hash is too long (should be 32 bytes)",
            }),
        })?;
        Ok(out)
    }

    fn parse_work_json(json: &Value) -> Result<[u8; 8], Value> {
        let root = json.get("work").ok_or(json!({
            "error": "Failed to deserialize JSON",
            "hint": "Work field missing",
        }))?;
        let mut out = [0u8; 8];
        Self::parse_hex_json(&root, &mut out, true).map_err(|err| match err {
            HexJsonError::Empty => json!({
                "error": "Failed to deserialize JSON",
                "hint": "Work is empty. Expecting a hex string",
            }),
            HexJsonError::InvalidHex => json!({
                "error": "Failed to deserialize JSON",
                "hint": "Expecting a hex string for work",
            }),
            HexJsonError::TooShort => panic!("Unexpected error HexJsonError::TooShort"),
            HexJsonError::TooLong => json!({
                "error": "Failed to deserialize JSON",
                "hint": "Work is too long (should be 8 bytes)",
            }),
        })?;
        out.reverse();
        Ok(out)
    }

    fn parse_difficulty_json(json: &Value) -> Result<Option<u64>, Value> {
        match json.get("difficulty") {
            None => Ok(None),
            Some(json) => {
                let difficulty_str = json.as_str().ok_or(json!({
                    "error": "Failed to deserialize JSON",
                    "hint": "Expecting a hex string for difficulty",
                }))?;
                let difficulty = u64::from_str_radix(difficulty_str, 16).map_err(|_| json!({
                    "error": "Failed to deserialize JSON",
                    "hint": "Threshold not a valid unsigned long (u64). Example: 'ffffffc000000000'",
                }))?;
                Ok(Some(difficulty))
            }
        }
    }

    fn parse_multiplier_json(json: &Value) -> Result<Option<f64>, Value> {
        match json.get("multiplier") {
            None => Ok(None),
            Some(json) => {
                let multiplier = json
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .filter(|&x| x > 0.)
                    .ok_or(json!({
                        "error": "Failed to deserialize JSON",
                        "hint": "Expecting a positive number for multiplier"
                    }))?;
                Ok(Some(multiplier))
            }
        }
    }

    fn parse_count_json(json: &Value) -> Result<u64, Value> {
        match json.get("count") {
            None => Err(json!({
                "error": "Failed to deserialize JSON",
                "hint": "count field missing"
            })),
            Some(json) => {
                let count = json
                    .as_u64()
                    .filter(|&x| x > 0)
                    .or(json
                        .as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .filter(|&x| x > 0))
                    .ok_or(json!({
                        "error": "Failed to deserialize JSON",
                        "hint": "Expecting a positive number for count"
                    }))?;
                Ok(count)
            }
        }
    }

    fn parse_json(&self, json: Value) -> Result<RpcCommand, Value> {
        match json.get("action") {
            None => {
                return Err(json!({
                    "error": "Failed to deserialize JSON",
                    "hint": "Work field missing",
                }))
            }
            Some(action) if action == "work_generate" => Ok(RpcCommand::WorkGenerate(
                Self::parse_hash_json(&json)?,
                Self::parse_difficulty_json(&json)?,
                Self::parse_multiplier_json(&json)?,
            )),
            Some(action) if action == "work_cancel" => {
                Ok(RpcCommand::WorkCancel(Self::parse_hash_json(&json)?))
            }
            Some(action) if action == "work_validate" => Ok(RpcCommand::WorkValidate(
                Self::parse_hash_json(&json)?,
                Self::parse_work_json(&json)?,
                Self::parse_difficulty_json(&json)?,
                Self::parse_multiplier_json(&json)?,
            )),
            Some(action) if action == "benchmark" => Ok(RpcCommand::Benchmark(
                Self::parse_difficulty_json(&json)?,
                Self::parse_multiplier_json(&json)?,
                Self::parse_count_json(&json)?,
            )),
            Some(action) if action == "status" => Ok(RpcCommand::Status()),
            Some(_) => {
                return Err(json!({
                    "error": "Unknown command",
                    "hint": "Supported commands: work_generate, work_cancel, work_validate, benchmark, status"
                }))
            }
        }
    }

    async fn process_req(self, body: &[u8]) -> hyper::Result<(StatusCode, Value)> {
        let json = match serde_json::from_slice(body) {
            Ok(json) => json,
            Err(_) => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    json!({
                        "error": "Failed to deserialize JSON",
                    }),
                ));
            }
        };
        let command = match self.parse_json(json) {
            Ok(r) => r,
            Err(err) => return Ok((StatusCode::BAD_REQUEST, err)),
        };
        let start = Instant::now();
        match command {
            RpcCommand::WorkGenerate(root, difficulty, multiplier) => {
                let now = Utc::now();
                let _ = println!(
                    "{} Received work for {}",
                    now.format("%T"),
                    hex::encode_upper(&root)
                );
                let difficulty = match multiplier {
                    None => difficulty.unwrap_or(LIVE_DIFFICULTY),
                    Some(multiplier) => self.from_multiplier(multiplier),
                };
                match self.generate_work(root, difficulty).await {
                    Ok(mut work) => {
                        let work_difficulty = work_value(root, work);
                        let work_multiplier = self.to_multiplier(work_difficulty);
                        let now = Utc::now();
                        let _ = println!(
                            "{} Generated for {} in {}ms for difficulty {:X}",
                            now.format("%T"),
                            hex::encode_upper(&root),
                            start.elapsed().as_millis(),
                            difficulty
                        );
                        // Reverse before encoding
                        work.reverse();
                        Ok((
                            StatusCode::OK,
                            json!({
                                "work": hex::encode(&work),
                                "difficulty": format!("{:X}", work_difficulty),
                                "multiplier": format!("{}", work_multiplier),
                            }),
                        ))
                    }
                    Err(WorkError::Canceled) => Ok((
                        StatusCode::OK,
                        json!({
                            "error": "Cancelled",
                        }),
                    )),
                    Err(WorkError::Errored) => Ok((
                        StatusCode::OK,
                        json!({
                            "error": "Work generation failed (see logs for details)",
                        }),
                    )),
                }
            }
            RpcCommand::WorkCancel(root) => {
                let _ = println!("Cancel {}", hex::encode_upper(&root));
                self.cancel_work(root);
                Ok((StatusCode::OK, json!({})))
            }
            RpcCommand::WorkValidate(root, work, difficulty, multiplier) => {
                let _ = println!("Validate {}", hex::encode_upper(&root));
                let difficulty_l = match multiplier {
                    None => difficulty.unwrap_or(LIVE_DIFFICULTY),
                    Some(multiplier) => self.from_multiplier(multiplier),
                };
                let (valid, work_difficulty) = work_valid(root, work, difficulty_l);
                let (valid_all, _) = work_valid(root, work, LIVE_DIFFICULTY);
                let (valid_receive, _) = work_valid(root, work, LIVE_RECEIVE_DIFFICULTY);
                let mut result = json!({
                    "valid_all": if valid_all { "1" } else { "0" },
                    "valid_receive": if valid_receive { "1" } else { "0" },
                    "difficulty": format!("{:X}", work_difficulty),
                    "multiplier": format!("{}", self.to_multiplier(work_difficulty)),
                });
                if difficulty.is_some() {
                    result
                        .as_object_mut()
                        .unwrap()
                        .insert(String::from("valid"), json!(if valid { "1" } else { "0" }));
                }
                Ok((StatusCode::OK, result))
            }
            RpcCommand::Benchmark(difficulty, multiplier, count) => {
                let difficulty_l = match multiplier {
                    None => difficulty.unwrap_or(LIVE_DIFFICULTY),
                    Some(multiplier) => self.from_multiplier(multiplier),
                };
                let multiplier_l = self.to_multiplier(difficulty_l);
                let _ = println!(
                    "Benchmarking {count} samples at difficulty {difficulty_l:X} ({multiplier_l}x)"
                );
                let mut roots: Vec<[u8; 32]> = Vec::new();
                roots.reserve(count as usize);
                for _ in 0..count {
                    roots.push(rand::random())
                }
                let start = Instant::now();
                for root in roots {
                    if self.generate_work(root, difficulty_l).await.is_err() {
                        return Ok((StatusCode::INTERNAL_SERVER_ERROR, {
                            json!({
                                "error": "Benchmark failed",
                                "hint": "Work generation failure",
                            })
                        }));
                    }
                }
                let duration = start.elapsed().as_millis();
                let average = duration as u64 / count;
                println!("Benchmark finished in {duration}ms (average {average}ms)");
                Ok((StatusCode::OK, {
                    json!({
                        "difficulty": format!("{:X}", difficulty_l),
                        "multiplier": format!("{}", multiplier_l),
                        "count": format!("{}", count),
                        "duration": format!("{}", duration),
                        "average": format!("{}", average),
                        "hint": "Times in milliseconds",
                    })
                }))
            }
            RpcCommand::Status() => {
                let state = self.work_state.0.lock();
                let queue_size = state.future_work.len();
                let resp = json!({
                    "queue_size": format!("{}", queue_size),
                    "generating": if state.task_working.load(Ordering::Relaxed) {"1"} else {"0"},
                });
                println!("Status {resp}");
                Ok((StatusCode::OK, resp))
            }
        }
    }

    async fn handle_request(self, mut req: Request<Body>) -> hyper::Result<Response<Body>> {
        let (status, body) = if *req.method() == Method::POST {
            let self_copy = self.clone();
            let body = hyper::body::to_bytes(req.body_mut()).await?;
            self_copy.process_req(body.as_ref()).await?
        } else {
            (
                StatusCode::METHOD_NOT_ALLOWED,
                json!({
                    "error": "Can only POST requests",
                }),
            )
        };
        let body_str = body.to_string();
        let body_len = body_str.len();
        let body = Body::from(body_str);
        Ok(Response::builder()
            .header(hyper::header::CONTENT_LENGTH, body_len)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .status(status)
            .body(body)
            .expect("Failed to build response"))
    }
}

pub async fn start_server(
    listen_addr: SocketAddr,
    gpus: Vec<Gpu>,
    cpu_threads: usize,
    n_workers: usize,
    random_mode: bool,
) {
    // Initialize shared work state and spawn workers:
    let work_state = Arc::new((Mutex::new(WorkState::default()), Condvar::new()));
    {
        let mut state = work_state.0.lock();
        state.task_working.store(false, Ordering::Relaxed);
        state.random_mode = random_mode;
    }

    // CPU worker threads
    for _ in 0..cpu_threads {
        let work_state = work_state.clone();
        let mut rng = XorShiftRng::from_rng(thread_rng()).expect("Failed to create XorShiftRng");
        thread::spawn(move || {
            let mut root = [0u8; 32];
            let mut difficulty = 0u64;
            let mut task_working = Arc::new(AtomicBool::new(false));
            loop {
                if !task_working.load(Ordering::Relaxed) {
                    let mut state = work_state.0.lock();
                    while state.callback.is_none() {
                        work_state.1.wait(&mut state);
                    }
                    root = state.root;
                    difficulty = state.difficulty;
                    task_working = state.task_working.clone();
                }
                let mut work: [u8; 8] = rng.gen();
                for _ in 0..(1 << 18) {
                    if work_valid(root, work, difficulty).0 {
                        let mut state = work_state.0.lock();
                        if root == state.root {
                            if let Some(callback) = state.callback.take() {
                                let _ = callback.send(Ok(work));
                                state.set_task(&work_state.1);
                            }
                        }
                        break;
                    }
                    for byte in work.iter_mut() {
                        *byte = byte.wrapping_add(1);
                        if *byte != 0 {
                            break;
                        }
                    }
                }
            }
        });
    }
    // GPU worker threads
    for (gpu_i, mut gpu) in gpus.into_iter().enumerate() {
        let work_state = work_state.clone();
        thread::spawn(move || {
            let mut failed = false;
            let mut rng =
                XorShiftRng::from_rng(thread_rng()).expect("Failed to create XorShiftRng");
            let mut root = [0u8; 32];
            let mut difficulty = 0u64;
            let mut task_working = Arc::new(AtomicBool::new(false));
            let mut consecutive_gpu_errors = 0;
            let mut consecutive_gpu_invalid_work_errors = 0;
            loop {
                if failed || !task_working.load(Ordering::Relaxed) {
                    let mut state = work_state.0.lock();
                    if root != state.root {
                        failed = false;
                    }
                    if failed {
                        state.unsuccessful_workers += 1;
                        if state.unsuccessful_workers == n_workers {
                            if let Some(callback) = state.callback.take() {
                                let _ = callback.send(Err(WorkError::Errored));
                                state.set_task(&work_state.1);
                            }
                        }
                        work_state.1.wait(&mut state);
                    }
                    while state.callback.is_none() {
                        work_state.1.wait(&mut state);
                    }
                    root = state.root;
                    difficulty = state.difficulty;
                    task_working = state.task_working.clone();
                    if failed {
                        state.unsuccessful_workers -= 1;
                    }
                    if let Err(err) = gpu.set_task(&root, difficulty) {
                        eprintln!("Failed to set GPU {gpu_i}'s task, abandoning it for this work: {err:?}");
                        failed = true;
                        continue;
                    }
                    failed = false;
                    consecutive_gpu_errors = 0;
                }
                let attempt: u64 = rng.gen();
                let mut work = [0u8; 8];
                match gpu.run(attempt, &mut work) {
                    Ok(true) => {
                        if work_valid(root, work, difficulty).0 {
                            let mut state = work_state.0.lock();
                            if root == state.root {
                                if let Some(callback) = state.callback.take() {
                                    let _ = callback.send(Ok(work));
                                    state.set_task(&work_state.1);
                                }
                            }
                            consecutive_gpu_errors = 0;
                            consecutive_gpu_invalid_work_errors = 0;
                        } else {
                            eprintln!(
                                "GPU {} returned invalid work {} for root {}",
                                gpu_i,
                                hex::encode(&work),
                                hex::encode_upper(&root),
                            );
                            consecutive_gpu_invalid_work_errors += 1;
                            if consecutive_gpu_invalid_work_errors >= 3 {
                                eprintln!("GPU {gpu_i} returned invalid work 3 consecutive times, abandoning it for this work");
                                failed = true;
                            } else {
                                consecutive_gpu_errors += 1;
                            }
                        }
                    }
                    Ok(false) => consecutive_gpu_errors = 0,
                    Err(err) => {
                        eprintln!("Error computing work on GPU {gpu_i}: {err:?}");
                        if let Err(err) = gpu.reset_bufs() {
                            eprintln!("Failed to reset GPU {gpu_i}'s buffers, abandoning it for this work: {err:?}");
                            failed = true;
                        }
                        consecutive_gpu_errors += 1;
                        if consecutive_gpu_errors >= 3 {
                            eprintln!(
                                "3 consecutive GPU {gpu_i} errors, abandoning it for this work"
                            );
                            failed = true;
                        }
                    }
                }
            }
        });
    }

    let service = RpcService {
        work_state: work_state.clone(),
    };
    let make_service = make_service_fn(move |_| {
        let service = service.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| service.clone().handle_request(req))) }
    });
    let server = Server::bind(&listen_addr).serve(make_service);

    println!("Difficulty set at {LIVE_DIFFICULTY:X}");
    println!("Listening on {listen_addr}");
    server.await.expect("Failed to serve requests");
}
