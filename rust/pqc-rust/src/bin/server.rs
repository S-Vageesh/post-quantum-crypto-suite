use axum::{
    extract::Json,
    http::StatusCode,
    routing::post,
    Router,
};
use pqc_rust::{Kem, KemAlgorithm, Kyber, KemPublicKey, KemSecretKey, Ciphertext};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use rand::rngs::OsRng;

#[derive(Serialize)]
struct KeyPairResponse {
    public_key: String,
    secret_key: String,
}

#[derive(Deserialize)]
struct EncapsulateRequest {
    public_key: String,
}

#[derive(Serialize)]
struct EncapsulateResponse {
    ciphertext: String,
    shared_secret: String,
}

#[derive(Deserialize)]
struct DecapsulateRequest {
    secret_key: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct DecapsulateResponse {
    shared_secret: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

async fn generate_keypair() -> Result<Json<KeyPairResponse>, (StatusCode, Json<ErrorResponse>)> {
    let kyber = Kyber::new(KemAlgorithm::Kyber768)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
    
    let (pk, sk) = kyber.generate_keypair(&mut OsRng)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;

    Ok(Json(KeyPairResponse {
        public_key: hex::encode(pk.as_bytes()),
        secret_key: hex::encode(sk.expose_secret()),
    }))
}

async fn encapsulate(
    Json(payload): Json<EncapsulateRequest>,
) -> Result<Json<EncapsulateResponse>, (StatusCode, Json<ErrorResponse>)> {
    let kyber = Kyber::new(KemAlgorithm::Kyber768)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;

    let pk_bytes = hex::decode(&payload.public_key)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid hex for public key".into() })))?;
    
    let pk = KemPublicKey::from_bytes(KemAlgorithm::Kyber768, pk_bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() })))?;

    let (ct, ss) = kyber.encapsulate(&pk, &mut OsRng)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;

    Ok(Json(EncapsulateResponse {
        ciphertext: hex::encode(ct.as_bytes()),
        shared_secret: hex::encode(ss.expose_secret()),
    }))
}

async fn decapsulate(
    Json(payload): Json<DecapsulateRequest>,
) -> Result<Json<DecapsulateResponse>, (StatusCode, Json<ErrorResponse>)> {
    let kyber = Kyber::new(KemAlgorithm::Kyber768)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;

    let sk_bytes = hex::decode(&payload.secret_key)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid hex for secret key".into() })))?;
    
    let sk = KemSecretKey::from_bytes(KemAlgorithm::Kyber768, sk_bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() })))?;

    let ct_bytes = hex::decode(&payload.ciphertext)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid hex for ciphertext".into() })))?;
    
    let ct = Ciphertext::from_bytes(KemAlgorithm::Kyber768, ct_bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() })))?;

    let ss = kyber.decapsulate(&ct, &sk)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;

    Ok(Json(DecapsulateResponse {
        shared_secret: hex::encode(ss.expose_secret()),
    }))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/kyber/keypair", post(generate_keypair))
        .route("/api/kyber/encapsulate", post(encapsulate))
        .route("/api/kyber/decapsulate", post(decapsulate))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001").await.unwrap();
    println!("Server running on http://127.0.0.1:3001");
    axum::serve(listener, app).await.unwrap();
}
