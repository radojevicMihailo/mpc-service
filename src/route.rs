use axum::{
    routing::get,
    Router,
};

use crate::{
    handler::{
        health_checker_handler, key_generation_handler, sign_transaction_handler
    },
};

pub fn create_router() -> Router {

    Router::new()
        .route("/healthchecker", get(health_checker_handler))
        .route(
            "/key-generation",
            get(key_generation_handler),
        )
        .route(
            "/sign-transaction",
            get(sign_transaction_handler)
        )
}