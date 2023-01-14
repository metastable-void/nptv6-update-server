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
use hyper::{Body, Request, Response, Server, Method, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use tokio::process::Command;
use url::Url;
use std::path::PathBuf;
use serde_json::{json, Value};
use clap_verbosity_flag::{Verbosity, InfoLevel};

#[derive(Debug, Parser)]
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

  /// Tell me more (or less)
  #[clap(flatten)]
  verbose: Verbosity<InfoLevel>,
}

struct RequestWithAddr {
  req: Request<Body>,
  addr: SocketAddr,
}

#[derive(Clone)]
struct Ip6tablesPaths {
  ip6tables_template: PathBuf,
  ip6tables_output: PathBuf,
}

#[derive(Clone)]
struct Configuration {
  secret: String,
  local_prefix: String,
  ip6tables_paths: Ip6tablesPaths,
}

impl Configuration {
  fn secret(&self) -> &str {
    &self.secret
  }
}

#[derive(Clone)]
struct ServiceError {
  status: StatusCode,
  message: String,
}

impl ServiceError {
  fn new(status: StatusCode, message: String) -> Self {
    Self { status, message }
  }
}

fn create_json_responce(status: StatusCode, json: Value) -> Response<Body> {
  Response::builder()
    .status(status)
    .header("Content-Type", "application/json")
    .body(Body::from(json.to_string()))
    .unwrap()
}

async fn update_ip6tables(req_addr: RequestWithAddr, config: Configuration) -> Result<(), ServiceError> {
  let req = req_addr.req;
  let Configuration {secret, local_prefix, ip6tables_paths} = config;
  let Ip6tablesPaths {ip6tables_template, ip6tables_output} = ip6tables_paths;
  let uri = req.uri();
  let path = uri.path();
  let target_path = format!("/{}", secret);
  if path != target_path {
    return Err(ServiceError::new(StatusCode::NOT_FOUND, format!("invalid path: {}", path)))
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
    return Err(ServiceError::new(StatusCode::BAD_REQUEST, format!("missing prefix")))
  }

  log::debug!("updating ip6tables rules using global prefix {}", &prefix);

  let ip6tables_template_content : String;
  if let Ok(content) = fs::read_to_string(&ip6tables_template).await {
    ip6tables_template_content = content;
  } else {
    return Err(ServiceError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to read ip6tables template: {:?}", &ip6tables_template)))
  }

  let ip6tables = ip6tables_template_content
    .replace("%LOCAL_PREFIX%", &local_prefix)
    .replace("%GLOBAL_PREFIX%", &prefix);
  
  if let Err(err) = fs::write(&ip6tables_output, ip6tables).await {
    return Err(ServiceError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write ip6tables rules: {:?} ({})", &ip6tables_output, err)))
  }

  let ip6tables_file;
  match fs::File::open(&ip6tables_output).await {
    Ok(file) => {
      ip6tables_file = file.into_std().await;
    },
    Err(err) => {
      return Err(ServiceError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to open ip6tables rules: {:?} ({})", &ip6tables_output, err)))
    }
  }
  match Command::new("ip6tables-restore")
    .stdin(ip6tables_file)
    .output()
    .await {
      Ok(output) => {
        if !output.status.success() {
          let ip6tables_output = String::from_utf8(output.stdout).unwrap_or("".to_string());
          return Err(ServiceError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("ip6tables-restore failed with exit code {} ({:?})", output.status, &ip6tables_output)))
        }
      },
      Err(err) => {
        return Err(ServiceError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("ip6tables-restore failed with {:?}", err)))
      }
    }
  
  log::info!("updated ip6tables rules using global prefix: {}", &prefix);
  Ok(())
}

/// Handle incoming HTTP requests
/// For security, this does not output on success
async fn handle_request(req_addr: RequestWithAddr, config: Configuration) -> Result<(), ServiceError> {
  let req = req_addr.req;
  let addr = req_addr.addr;
  let method = req.method();
  let uri = req.uri();
  let secret = config.secret();

  log::debug!("{}: {} {}", &addr, method, uri);

  let target_path = format!("/update/{}", secret);
  match (method, uri.path().to_string() == target_path) {
    (&Method::GET, true) => {
      let req_addr = RequestWithAddr {req, addr: addr};
      update_ip6tables(req_addr, config).await
    },

    (_, true) => {
      Err(ServiceError::new(StatusCode::METHOD_NOT_ALLOWED, format!("invalid method: {}", method)))
    },

    (&Method::GET, false) => {
      Err(ServiceError::new(StatusCode::NOT_FOUND, format!("invalid path: {}", uri)))
    },

    _ => {
      Err(ServiceError::new(StatusCode::BAD_REQUEST, format!("invalid request: {}", req.uri())))
    }
  }
}

async fn format_json_responce(req_addr: RequestWithAddr, config: Configuration) -> Result<Response<Body>, Infallible> {
  match handle_request(req_addr, config).await {
    Ok(_) => Ok(create_json_responce(StatusCode::OK, json!({
      "error": Value::Null,
    }))),

    Err(err) => {
      log::error!("error: {}", &err.message);
      Ok(create_json_responce(err.status, json!({
        "error": &err.message,
      })))
    }
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let args: Args = Args::parse();
  env_logger::builder()
    .default_format()
    .write_style(env_logger::WriteStyle::Never)
    .filter_level(args.verbose.log_level_filter())
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
        let req_addr = RequestWithAddr {
          req: req,
          addr: addr.clone(),
        };
        let ip6tables_paths = Ip6tablesPaths {
          ip6tables_template: ip6tables_template.clone(),
          ip6tables_output: ip6tables_output.clone(),
        };
        let config = Configuration {
          secret: secret.clone(),
          local_prefix: local_prefix.clone(),
          ip6tables_paths: ip6tables_paths,
        };
        format_json_responce(req_addr, config)
      }))
      }
  });

  let server = Server::bind(&addr).serve(make_svc);

  log::info!("Listening on http://{} - awaiting requests at /update/<secret>", &addr);
  // Run this server for... forever!
  if let Err(e) = server.await {
    log::error!("server error: {}", e);
  }

  Ok(())
}
