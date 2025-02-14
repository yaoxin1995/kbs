// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Confidential Containers Key Broker Service

extern crate anyhow;

use anyhow::{bail, Result};
use api_server::{attest::AttestVerifier, config::Config, ApiServer};
use log::warn;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::Parser;

static SESSION_TIMEOUT: i64 = 5;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Socket address (IP:port) to listen to, e.g. 127.0.0.1:8080.
    /// This can be set multiple times.
    #[arg(required = true, short, long)]
    socket: Vec<SocketAddr>,

    /// HTTPS session timeout (in minutes)
    #[arg(default_value_t = SESSION_TIMEOUT, short, long)]
    timeout: i64,

    /// HTTPS private key
    #[arg(short, long)]
    private_key: Option<PathBuf>,

    /// HTTPS Certificate
    #[arg(long)]
    certificate: Option<PathBuf>,

    /// Insecure HTTP.
    /// WARNING Using this option makes the HTTP connection insecure.
    #[arg(default_value_t = false, long)]
    insecure_http: bool,

    /// KBS config file path.
    #[arg(default_value_t = String::default(), short, long)]
    config: String,

    /// Public key used to authenticate the resource registration endpoint token (JWT).
    /// Only JWTs signed with the corresponding private keys will be authenticated.
    #[arg(long)]
    auth_public_key: Option<PathBuf>,

    /// Insecure HTTP Apis.
    /// WARNING Using this option enables insecure APIs of KBS, such as
    /// - Resource Registration without verifying the JWK.
    #[arg(default_value_t = false, short, long)]
    insecure_api: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    env_logger::Builder::new()
    .parse_filters("error")
    .init();

    let cli = Cli::parse();
    let kbs_config = match cli.config.as_str() {
        "" => Config::default(),
        _ => Config::try_from(Path::new(&cli.config))?,
    };

    if !cli.insecure_http && (cli.private_key.is_none() || cli.certificate.is_none()) {
        bail!("Missing HTTPS credentials");
    }

    if cli.insecure_api {
        warn!("insecure apis are enabled.");
    }

    let attestation_service = AttestVerifier::new(&kbs_config).await?;

    let api_server = ApiServer::new(
        kbs_config,
        cli.socket,
        cli.private_key,
        cli.auth_public_key,
        cli.certificate,
        cli.insecure_http,
        attestation_service,
        cli.timeout,
        cli.insecure_api,
    )?;

    api_server.serve().await.map_err(anyhow::Error::from)
}
