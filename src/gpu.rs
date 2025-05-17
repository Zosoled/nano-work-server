use ocl;
use ocl::builders::DeviceSpecifier;
use ocl::builders::ProgramBuilder;
use ocl::flags::MemFlags;
use ocl::Buffer;
use ocl::Platform;
use ocl::ProQue;
use ocl::Result;

use byteorder::{ByteOrder, LittleEndian};

pub struct Gpu {
    kernel: ocl::Kernel,
    work: Buffer<u8>,
    seed: Buffer<u8>,
    hash: Buffer<u8>,
}

impl Gpu {
    pub fn new(
        platform_idx: usize,
        device_idx: usize,
        threads: usize,
        local_work_size: Option<usize>,
    ) -> Result<Gpu> {
        let mut prog_bldr = ProgramBuilder::new();
        prog_bldr.src(include_str!("work.cl"));
        let platforms = Platform::list();
        if platforms.len() == 0 {
            return Err("No OpenCL platforms exist (check your drivers and OpenCL setup)".into());
        }
        if platform_idx >= platforms.len() {
            return Err(format!(
                "Platform index {} too large (max {})",
                platform_idx,
                platforms.len() - 1
            )
            .into());
        }
        let pro_que = ProQue::builder()
            .prog_bldr(prog_bldr)
            .platform(platforms[platform_idx])
            .device(DeviceSpecifier::Indices(vec![device_idx]))
            .dims(1)
            .build()?;

        let device = pro_que.device();
        println!(
            "Initializing GPU: {} {}",
            device.vendor().unwrap_or_else(|_| "[unknown]".into()),
            device.name().unwrap_or_else(|_| "[unknown]".into())
        );

        let work = Buffer::<u8>::builder()
            .queue(pro_que.queue().clone())
            .flags(MemFlags::new().write_only())
            .len(8)
            .build()?;
        let seed = Buffer::<u8>::builder()
            .queue(pro_que.queue().clone())
            .flags(MemFlags::new().read_only().host_write_only())
            .len(8)
            .build()?;
        let hash = Buffer::<u8>::builder()
            .queue(pro_que.queue().clone())
            .flags(MemFlags::new().read_only().host_write_only())
            .len(32)
            .build()?;

        let difficulty = 0u64;

        let kernel = {
            let mut kernel_builder = pro_que.kernel_builder("work_generate");
            kernel_builder
                .global_work_size(threads)
                .arg(&work)
                .arg(&seed)
                .arg(&hash)
                .arg_named("difficulty", &difficulty);
            if let Some(local_work_size) = local_work_size {
                kernel_builder.local_work_size(local_work_size);
            }
            kernel_builder.build()?
        };

        let mut gpu = Gpu {
            kernel,
            work,
            seed,
            hash,
        };
        gpu.reset_bufs()?;
        Ok(gpu)
    }

    pub fn reset_bufs(&mut self) -> Result<()> {
        self.work.write(&[0u8; 8] as &[u8]).enq()?;
        Ok(())
    }

    pub fn set_task(&mut self, hash: &[u8], difficulty: u64) -> Result<()> {
        self.reset_bufs()?;
        self.hash.write(hash).enq()?;
        self.kernel.set_arg("difficulty", difficulty)?;
        Ok(())
    }

    pub fn run(&mut self, out: &mut [u8], seed: u64) -> Result<bool> {
        let mut seed_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut seed_bytes, seed);
        self.seed.write(&seed_bytes as &[u8]).enq()?;
        debug_assert!(out.iter().all(|&b| b == 0));
        debug_assert!({
            let mut work = [0u8; 8];
            self.work.read(&mut work as &mut [u8]).enq()?;
            work.iter().all(|&b| b == 0)
        });

        unsafe {
            self.kernel.enq()?;
        }

        self.work.read(&mut *out).enq()?;
        let success = !out.iter().all(|&b| b == 0);
        if success {
            self.reset_bufs()?;
        }
        Ok(success)
    }
}
