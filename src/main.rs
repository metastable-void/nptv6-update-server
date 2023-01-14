// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=&2 sw=2 et ai :

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::fs;
use clap::Parser;
use hyper::server::conn::AddrStream;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use tokio::process::Command;
use url::Url;
use std::path::PathBuf;
use serde_json::{json, Value};
use log::LevelFilter;

#[derive(Parser)]
#[clap(version)]
struct Args {
  /// The address to listen on
  #[clap(short = 'a', long)]
  listen: String,

  /// The secret path to use
  #[clap(short = 's', long)]
  secret: String,

  /// The local ULA prefix to use
  #[clap(short = 'p', long)]
  local_prefix: String,

  /// ip6tables template path
  #[clap(short = 't', long)]
  ip6tables_template: PathBuf,

  /// The path to save ip6tables rules into
  #[clap(short = 'o', long)]
  ip6tables_output: PathBuf,

  /// The log level to use
  #[clap(short = 'l', long, default_value = LevelFilter::Info.as_str())]
  log_level: LevelFilter,
}

fn create_json_responce(status: u16, json: Value) -> Response<Body> {
  Response::builder()
    .status(status)
    .header("Content-Type", "application/json")
    .body(Body::from(json.to_string()))
    .unwrap()
}

async fn update_ip6tables(req: Request<Body>, _addr: SocketAddr, secret: String, local_prefix: String, ip6tables_template: PathBuf, ip6tables_output: PathBuf) -> Result<Response<Body>, Infallible> {
  let uri = req.uri();
  let path = uri.path();
  let target_path = format!("/{}", secret);
  if path != target_path {
    log::error!("invalid path: {}", path);
    return Ok(create_json_responce(404, json!({
      "error": "not found",
    })));
  }

  let url_obj = Url::parse(&req.uri().to_string()).unwrap();
  let params = url_obj.query_pairs();
  let mut prefix = "".to_string();
  for (key, value) in params {
    if key != "prefix" {
      continue;
    }
    prefix = value.to_string();
  }
  if prefix == "" {
    log::error!("missing prefix");
    return Ok(create_json_responce(500, json!({
      "error": "missing prefix",
    })));
  }

  let ip6tables_template_content : String;
  if let Ok(content) = fs::read_to_string(ip6tables_template).await {
    ip6tables_template_content = content;
  } else {
    log::error!("failed to read ip6tables template");
    return Ok(create_json_responce(500, json!({
      "error": "failed to read ip6tables template",
    })));
  }

  let ip6tables = ip6tables_template_content
    .replace("%LOCAL_PREFIX%", &local_prefix)
    .replace("%GLOBAL_PREFIX%", &prefix);
  
  if let Err(_) = fs::write(ip6tables_output.clone(), ip6tables).await {
    log::error!("failed to write ip6tables rules");
    return Ok(create_json_responce(500, json!({
      "error": "failed to write ip6tables rules",
    })));
  }

  let ip6tables_file = fs::File::open(ip6tables_output).await.unwrap().into_std().await;
  if let Err(_) = Command::new("ip6tables-restore")
    .stdin(ip6tables_file)
    .output()
    .await {
      log::error!("ip6tables-restore failed");
      return Ok(create_json_responce(500, json!({
        "error": "ip6tables-restore failed",
      })))
    }
  
  log::info!("updated ip6tables rules using global prefix: {}", &prefix);
  Ok(create_json_responce(200, json!({
    "error": Value::Null,
  })))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let args: Args = Args::parse();
  env_logger::builder()
    .default_format()
    .write_style(env_logger::WriteStyle::Never)
    .filter_level(args.log_level)
    .init();
  
  let addr = SocketAddr::from_str(&args.listen).unwrap_or(SocketAddr::from(([127, 0, 0, 1], 8080)));
  
  let make_svc = make_service_fn(move |conn: &AddrStream| {
    let addr = conn.remote_addr();
    let secret = args.secret.clone();
    let local_prefix = args.local_prefix.clone();
    let ip6tables_template = args.ip6tables_template.clone();
    let ip6tables_output = args.ip6tables_output.clone();
    async move {
        let addr = addr.clone();
        Ok::<_, Infallible>(service_fn(move |req : Request<Body>| {
            update_ip6tables(req, addr, secret.clone(), local_prefix.clone(), ip6tables_template.clone(), ip6tables_output.clone())
        }))
      }
  });

  let server = Server::bind(&addr).serve(make_svc);

  log::info!("Listening on http://{}", &addr);
  // Run this server for... forever!
  if let Err(e) = server.await {
      eprintln!("server error: {}", e);
  }

  Ok(())
}
