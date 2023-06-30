// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::Attest;
use anyhow::*;
use as_types::AttestationResults;
use async_trait::async_trait;
use attestation_service::{config::Config as AsConfig, AttestationService};
use kbs_types::Tee;
use std::path::Path;
use base64ct::{Base64, Encoding};
use sha2::Sha512;
use sha2::Digest;
use kbs_types::Attestation;
use serde_derive::Deserialize;
use serde_derive::Serialize;

pub struct Native {
    inner: AttestationService,
}

#[async_trait]
impl Attest for Native {
    async fn attest_verify(
        &mut self,
        tee: Tee,
        nonce: &str,
        attestation: &str,
    ) -> Result<AttestationResults> {


        // self.inner.evaluate(tee, nonce, attestation).await;

        let attestation = serde_json::from_str::<Attestation>(attestation)
        .context("Failed to deserialize Attestation")?;

        let result = quark_vrifier(attestation, nonce).await;
        
        log::error!("attest_verify result {:?}", result);

        let attestation_results =AttestationResults::new(tee, result, None, None, None);


        return Ok(attestation_results);


    }
}

impl Native {
    pub fn new(as_config_path: &Option<String>) -> Result<Self> {
        let as_config = match as_config_path {
            Some(path) => AsConfig::try_from(Path::new(&path))
                .map_err(|e| anyhow!("Read AS config file failed: {:?}", e))?,
            None => AsConfig::default(),
        };

        Ok(Self {
            inner: AttestationService::new(as_config)?,
        })
    }
}



#[repr(C)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcbVersion {
    pub boot_loader: u8,
    pub tee: u8,
    pub reserved: Vec<u8>,
    pub snp: u8,
    pub microcode: u8,
    pub raw: Vec<u8>,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SnpAttestationReportSignature {
	pub r: Vec<u8>, // 72 bytes,
	pub s: Vec<u8>, //72 bytes,
	pub reserved: Vec<u8>,  // 368 bytes,
}


#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AttestationReport {
	pub version: u32,		/* 0x000 */
	pub guest_svn: u32,	/* 0x004 */
	pub policy: u64,			/* 0x008 */
	pub family_id: Vec<u8>, /* 16 bytes, 0x010 */
	pub image_id: Vec<u8>, /*16 bytes, 0x020 */
	pub vmpl: u32,				/* 0x030 */
	pub signature_algo: u32,		/* 0x034 */
	pub platform_version: TcbVersion,  /* 0x038 */
	pub platform_info: u64,		/* 0x040 */
	pub flags: u32,			/* 0x048 */
	pub reserved0: u32,		/* 0x04C */
	pub report_data: Vec<u8>, /*64 bytes, 0x050 */
	pub measurement: Vec<u8>, 	/*48 bytes, 0x090 */
	pub host_data: Vec<u8>, /*32 bytes, 0x0C0 */
	pub id_key_digest: Vec<u8>, /*48 bytes, 0x0E0 */
	pub author_key_digest: Vec<u8>, /*48 bytes, 0x110 */
	pub report_id: Vec<u8>, /*32 bytes, 0x140 */
	pub report_id_ma: Vec<u8>, 	/*32 bytes, 0x160 */
	pub reported_tcb: TcbVersion,	/* 0x180 */
	pub reserved1: Vec<u8>, /*24 bytes, 0x188 */
	pub chip_id: Vec<u8>, /*64 bytes, 0x1A0 */
	pub reserved2: Vec<u8>, /*192 bytes, 0x1E0 */
	pub signature: SnpAttestationReportSignature  /* 0x2A0 */
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SingleShotCommandLineModeConfig {
    pub allowed_cmd: Vec<String>,
    pub allowed_dir: Vec<String>,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct PrivilegedUserConfig {
    pub enable_terminal: bool,
    pub enable_single_shot_command_line_mode: bool,
    pub single_shot_command_line_mode_configs : SingleShotCommandLineModeConfig,
    pub exec_result_encryption: bool,
    pub enable_container_logs_encryption:bool,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct UnprivilegedUserConfig {
    pub enable_terminal: bool,
    pub enable_single_shot_command_line_mode: bool,
    pub single_shot_command_line_mode_configs : SingleShotCommandLineModeConfig,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct EnvCmdBasedSecrets {
    pub env_variables: Vec<String>,
    pub cmd_arg: Vec<String>,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum DefaultAction {
#[warn(non_camel_case_types)]
    #[default]  
    ScmpActErrno,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum SystemCallInterceptorMode {
#[warn(non_camel_case_types)]
    #[default]  
    Global,  // the interceptor works globaly
    ContextBased, // the interceptor only works for application process
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct FrontEndSyscallInterceptorConfig {
    pub enable: bool,
    pub mode: SystemCallInterceptorMode,
    pub default_action: DefaultAction,
    pub syscalls: Vec<String>
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct BackEndSyscallInterceptorConfig {
    pub enable: bool,
    pub mode: SystemCallInterceptorMode,
    pub default_action: DefaultAction,
    pub syscalls: [u64; 8]
}

#[derive(Default, Clone, Copy, Debug, PartialOrd, Ord, Eq, PartialEq, Serialize, Deserialize)]
pub enum QkernelDebugLevel {
    #[default]
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}


#[derive(Default, Clone, Copy, Debug, PartialOrd, Ord, Eq, PartialEq, Serialize, Deserialize)]
pub struct QlogPolicy {
    pub enable: bool,
    pub allowed_max_log_level: QkernelDebugLevel
}

#[derive(Default, Clone, Copy, Debug, PartialOrd, Ord, Eq, PartialEq, Serialize, Deserialize)]
pub enum EnclaveMode {
    #[default]
    Development,
    Production
}


#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeReferenceMeasurement {
    #[serde(rename = "binary_name")]
    pub binary_name: String,
    #[serde(rename = "reference_measurement")]
    pub reference_measurement: String,
}





#[derive(Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct BackEndKbsPolicy {
    #[serde(rename = "app_launch_ref_measurement")]
    pub app_launch_ref_measurement: String,
    #[serde(rename = "runtime_reference_measurements")]
    pub runtime_reference_measurements: Vec<RuntimeReferenceMeasurement>,
    pub enclave_mode: EnclaveMode,
    pub enable_policy_updata: bool,
    pub privileged_user_config: PrivilegedUserConfig,
    pub unprivileged_user_config:  UnprivilegedUserConfig,
    pub privileged_user_key_slice: String,
    pub qkernel_log_config: QlogPolicy,
    pub syscall_interceptor_config: BackEndSyscallInterceptorConfig,
}

const BACKEND_POLICY_FILE_PATH: &str = "/opt/confidential-containers/kbs/repository/quark_nginx/nginx_resource/policy";


async fn load(policy_path: &str) -> Result<BackEndKbsPolicy> {

    let resource_byte = tokio::fs::read(&policy_path).await.context("read resource from local fs")?;
    let bytes = base64::decode(resource_byte)
    .context("Failed to deserialize resource_byte")?;
    
    let policy: BackEndKbsPolicy = serde_json::from_slice(&bytes)
    .context("load serde_json::from_slice failed to get secret")?;

    return Ok(policy);
}


async fn quark_vrifier(attesstation: Attestation, nonce: &str) -> bool {
    let snp_emulation_report= serde_json::from_str::<AttestationReport>(&attesstation.tee_evidence)
                .context("Failed to deserialize AttestationReport").unwrap();


    let user_data = snp_emulation_report.report_data;
    let user_data_string: String = Base64::encode_string(&user_data);

    let mut policy = load(BACKEND_POLICY_FILE_PATH).await.unwrap();


    if policy.enclave_mode == EnclaveMode::Development {

        log::error!("enclave is in development mode");
        return true;
    }


    let ref_ehd_chunks = vec![
        policy.app_launch_ref_measurement.clone().into_bytes(),
        nonce.to_string().into_bytes(),   // agains replay attack
        attesstation.tee_pubkey.k_mod.clone().into_bytes(),
        attesstation.tee_pubkey.k_exp.clone().into_bytes(),
    ];


    
    let ref_user_data = hash_chunks(ref_ehd_chunks);

    if user_data_string.eq(&ref_user_data) {

        log::error!("Authentication in production mode, the hash in the report's custom field matches the hash of (nonce, enclave_startup_measurement, and tee public key) generated in sm");
        return true;
    } else {
        log::error!("application launch measurement doesn't match the reference value");
        return false;
    }

}

pub fn hash_chunks(chunks: Vec<Vec<u8>>) -> String {
	let mut hasher = Sha512::new();

	for chunk in chunks.iter() {
		hasher.update(chunk);
	}

	let res = hasher.finalize();

	let base64 = Base64::encode_string(&res);

	base64
} 


