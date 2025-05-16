use ocl::{
    builders::{DeviceSpecifier, ProgramBuilder},
    flags::MemFlags,
    Buffer, Platform, ProQue, Result,
};

use byteorder::{ByteOrder, LittleEndian};

pub struct Gpu {
    kernel: ocl::Kernel,
    seed: Buffer<u8>,
    blockhash: Buffer<u8>,
    work: Buffer<u8>,
}

impl Gpu {
    pub fn new(
        platform_idx: usize,
        device_idx: usize,
        threads: usize,
        local_work_size: Option<usize>,
    ) -> Result<Self> {
        let mut prog_bldr = ProgramBuilder::new();
        prog_bldr.src(include_str!("work.cl"));

        let platforms = Platform::list();
        if platforms.is_empty() {
            return Err("No OpenCL platforms found".into());
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

        let seed = Buffer::<u8>::builder()
            .queue(pro_que.queue().clone())
            .flags(MemFlags::READ_ONLY | MemFlags::HOST_WRITE_ONLY)
            .len(8)
            .build()?;

        let blockhash = Buffer::<u8>::builder()
            .queue(pro_que.queue().clone())
            .flags(MemFlags::READ_ONLY | MemFlags::HOST_WRITE_ONLY)
            .len(32)
            .build()?;

        let work = Buffer::<u8>::builder()
            .queue(pro_que.queue().clone())
            .flags(MemFlags::WRITE_ONLY)
            .len(8)
            .build()?;

        let difficulty = 0u64;

        let mut kernel_builder = pro_que.kernel_builder("work_generate");
        if let Some(lws) = local_work_size {
            kernel_builder.local_work_size(lws);
        }
        kernel_builder
            .global_work_size(threads)
            .arg(&seed)
            .arg(&blockhash)
            .arg(&work)
            .arg_named("difficulty", &difficulty);
        let kernel = kernel_builder.build()?;

        let mut gpu = Gpu {
            kernel,
            seed,
            blockhash,
            work,
        };
        gpu.reset_bufs()?;
        Ok(gpu)
    }

    pub fn reset_bufs(&mut self) -> Result<()> {
        self.work.write(&[0u8; 8][..]).enq()?;
        Ok(())
    }

    pub fn set_task(&mut self, blockhash: &[u8], difficulty: u64) -> Result<()> {
        self.reset_bufs()?;
        self.blockhash.write(blockhash).enq()?;
        self.kernel.set_arg("difficulty", difficulty)?;
        Ok(())
    }

    pub fn run(&mut self, seed: u64, work: &mut [u8]) -> Result<bool> {
        let mut seed_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut seed_bytes, seed & 0x7fffffffffffffff);
        self.seed.write(&seed_bytes as &[u8]).enq()?;
        debug_assert!(work.iter().all(|&b| b == 0));
        debug_assert!({
            let mut work_check = [0u8; 8];
            self.work.read(&mut work_check as &mut [u8]).enq()?;
            work.iter().all(|&b| b == 0)
        });

        unsafe {
            self.kernel.enq()?;
        }

        self.work.read(&mut *work).enq()?;
        let found = work.iter().any(|&b| b != 0);
        if found {
            self.reset_bufs()?;
        }
        Ok(found)
    }
}
