// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=&2 sw=2 et ai :

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// TODO: Use POST

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::fs;
use clap::Parser;
use hyper::server::conn::AddrStream;
use hyper::{Body, Request, Response, Server, Method, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use tokio::process::Command;
use url::form_urlencoded::parse;
use std::path::{PathBuf, Path};
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

impl RequestWithAddr {
  fn new(req: Request<Body>, addr: SocketAddr) -> Self {
    Self { req, addr }
  }

  fn addr(&self) -> &SocketAddr {
    &self.addr
  }

  fn req_uri(&self) -> &hyper::Uri {
    self.req.uri()
  }

  async fn req_body_query_map(&mut self) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(mime) = self.req.headers().get("Content-Type") {
      if "application/x-www-form-urlencoded" != mime.to_str().unwrap() {
        return map;
      }
    } else {
      return map;
    }
    
    if let Ok(bytes) = hyper::body::to_bytes(self.req.body_mut()).await {
      for (key, value) in parse(&bytes) {
        map.insert(key.to_string(), value.to_string());
      }
    }
    
    map
  }

  fn req_method(&self) -> &Method {
    self.req.method()
  }
}

#[derive(Clone)]
struct Ip6tablesPaths {
  ip6tables_template: PathBuf,
  ip6tables_output: PathBuf,
}

impl Ip6tablesPaths {
  fn new(ip6tables_template: PathBuf, ip6tables_output: PathBuf) -> Self {
    Self { ip6tables_template, ip6tables_output }
  }

  fn template(&self) -> &Path {
    &self.ip6tables_template
  }

  fn output(&self) -> &Path {
    &self.ip6tables_output
  }
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

fn format_ip6tables(template: &str, local_prefix: &str, global_prefix: &str) -> String {
  template
    .replace("%LOCAL_PREFIX%", &local_prefix)
    .replace("%GLOBAL_PREFIX%", &global_prefix)
}

async fn run_ip6tables_restore(stdin_path: impl AsRef<Path>) -> Result<(), ServiceError> {
  let ip6tables_file;
  match fs::File::open(&stdin_path).await {
    Ok(file) => {
      ip6tables_file = file.into_std().await;
    },
    Err(err) => {
      return Err(ServiceError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to open ip6tables rules: {:?} ({})", &stdin_path.as_ref(), err)))
    }
  }

  match Command::new("ip6tables-restore").stdin(ip6tables_file).status().await {
    Ok(status) => {
      if !status.success() {
        return Err(ServiceError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("ip6tables-restore failed: {}", status)))
      }
    },

    Err(err) => {
      return Err(ServiceError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to run ip6tables-restore: {}", err)))
    }
  }
  Ok(())
}

async fn update_ip6tables(mut req_addr: RequestWithAddr, config: Configuration) -> Result<(), ServiceError> {
  let local_prefix = &config.local_prefix;
  let ip6tables_paths = &config.ip6tables_paths;

  let secret = config.secret();
  let post_query = req_addr.req_body_query_map().await;

  if let Some(s) = post_query.get("secret") {
    if s != secret {
      return Err(ServiceError::new(StatusCode::UNAUTHORIZED, format!("Invalid secret")))
    }
  } else {
    return Err(ServiceError::new(StatusCode::BAD_REQUEST, format!("missing secret")))
  }

  let prefix: String;
  if let Some(s) = post_query.get("prefix") {
    prefix = s.to_string();
  } else {
    return Err(ServiceError::new(StatusCode::BAD_REQUEST, format!("missing prefix")))
  }

  log::debug!("updating ip6tables rules using global prefix {}", &prefix);
  let template_path = ip6tables_paths.template();
  let output_path = ip6tables_paths.output();

  let ip6tables_template_content : String;
  if let Ok(content) = fs::read_to_string(template_path).await {
    ip6tables_template_content = content;
  } else {
    return Err(ServiceError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to read ip6tables template: {:?}", template_path)))
  }

  let ip6tables = format_ip6tables(&ip6tables_template_content, &local_prefix, &prefix);
  
  if let Err(err) = fs::write(output_path, ip6tables).await {
    return Err(ServiceError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write ip6tables rules: {:?} ({})", output_path, err)))
  }

  run_ip6tables_restore(output_path).await?;
  log::info!("updated ip6tables rules using global prefix: {}", &prefix);
  Ok(())
}

/// Handle incoming HTTP requests
/// For security, this does not output on success
async fn handle_request(req_addr: RequestWithAddr, config: Configuration) -> Result<(), ServiceError> {
  let addr = req_addr.addr();
  let method = req_addr.req_method();
  let uri = req_addr.req_uri();

  log::info!("{}: {} {}", addr, method, uri);

  match (method, uri.path()) {
    (&Method::GET, "/update") => {
      update_ip6tables(req_addr, config).await
    },

    (_, "/update") => {
      Err(ServiceError::new(StatusCode::METHOD_NOT_ALLOWED, format!("invalid method: {}", method)))
    },

    (&Method::GET, _) => {
      Err(ServiceError::new(StatusCode::NOT_FOUND, format!("invalid path: {}", uri)))
    },

    _ => {
      Err(ServiceError::new(StatusCode::BAD_REQUEST, format!("invalid request: {}", uri)))
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
        let req_addr = RequestWithAddr::new(req, addr.clone());
        let ip6tables_paths = Ip6tablesPaths::new(ip6tables_template.clone(), ip6tables_output.clone());
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

  log::info!("Listening on http://{} - awaiting requests at /update", &addr);
  // Run this server for... forever!
  if let Err(e) = server.await {
    log::error!("server error: {}", e);
  }

  Ok(())
}
