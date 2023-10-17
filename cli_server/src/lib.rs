use tonic::{transport::Server, Request, Response, Status};

use super::server::get_server::{Get, GetServer};
use super::server::{StatsRequest, StatsReply};

pub mod server {
    tonic::include_proto!("cli_server");
}
