use std::net::SocketAddr;
use std::path::PathBuf;

use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::routing::post;
use axum::Json;
use axum::Router;
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use ironsift::{
    AnoMarkSettings, AnoMarkTrainRequest, AutoPipelineRequest, CreateDatasetRequest,
    CreateRunRequest, DetectionConfig, PlatformStore, SigmaZeroCheckRequest, SigmaZeroSettings,
};

const UI_HTML: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/web/index.html"));

#[derive(Clone)]
struct AppState {
    store: PlatformStore,
}

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

#[derive(Debug, Deserialize)]
struct TagRequest {
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HoneycombQuery {
    run_id: String,
    min_score: Option<f64>,
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UploadQuery {
    name: Option<String>,
    tags: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = PlatformStore::load_or_create(".ironsift-platform/db.json")?;
    let state = AppState { store };

    let app = Router::new()
        .route("/", get(ui))
        .route("/api/health", get(health))
        .route("/api/datasets", get(list_datasets).post(create_dataset))
        .route("/api/datasets/purge", post(purge_datasets))
        .route("/api/datasets/:id/inspect", get(inspect_dataset))
        .route("/api/datasets/upload", post(upload_dataset))
        .route("/api/datasets/:id/tags", post(add_tags))
        .route("/api/runs/purge", post(purge_runs))
        .route("/api/runs", get(list_runs).post(create_run))
        .route(
            "/api/runs/:id",
            get(get_run).delete(delete_run),
        )
        .route("/api/runs/:id/detections", get(get_run_detections))
        .route("/api/fleet/honeycomb", get(get_honeycomb))
        .route("/api/pipeline/auto", post(run_auto_pipeline))
        .route("/api/anomark/config", get(get_anomark_config).post(set_anomark_config))
        .route("/api/anomark/availability", get(get_anomark_availability))
        .route("/api/anomark/train", post(train_anomark))
        .route("/api/anomark/trains", get(list_anomark_trains))
        .route(
            "/api/anomark/trains/:id/model",
            get(download_anomark_model),
        )
        .route(
            "/api/anomark/trains/:id/training-data",
            get(download_anomark_training_data),
        )
        .route("/api/run-config", get(get_run_config).post(set_run_config))
        .route("/api/sigma-zero/config", get(get_sigma_config).post(set_sigma_config))
        .route("/api/sigma-zero/check", post(check_sigma_zero))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8080".parse()?;
    println!("IronSift server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn ui() -> Html<&'static str> {
    Html(UI_HTML)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status":"ok"}))
}

async fn list_datasets(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "datasets": state.store.list_datasets() }))
}

async fn list_runs(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "runs": state.store.list_runs() }))
}

async fn create_dataset(
    State(state): State<AppState>,
    Json(req): Json<CreateDatasetRequest>,
) -> impl IntoResponse {
    match state.store.create_dataset(req) {
        Ok(ds) => (StatusCode::CREATED, Json(serde_json::json!({ "dataset": ds }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn add_tags(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<TagRequest>,
) -> impl IntoResponse {
    match state.store.add_dataset_tags(&id, &req.tags) {
        Ok(ds) => (StatusCode::OK, Json(serde_json::json!({ "dataset": ds }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn inspect_dataset(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.store.inspect_dataset(&id) {
        Ok(info) => (StatusCode::OK, Json(serde_json::json!({ "inspection": info }))).into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn purge_datasets(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.delete_all_datasets() {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn create_run(
    State(state): State<AppState>,
    Json(req): Json<CreateRunRequest>,
) -> impl IntoResponse {
    match state.store.run_detection(req) {
        Ok(run) => (StatusCode::CREATED, Json(serde_json::json!({ "run": run }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn delete_run(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.store.delete_run(&id) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            let code = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                code,
                Json(serde_json::to_value(ApiError { error: msg }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn purge_runs(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.delete_all_runs() {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn run_auto_pipeline(
    State(state): State<AppState>,
    Json(req): Json<AutoPipelineRequest>,
) -> impl IntoResponse {
    match state.store.run_auto_pipeline(req) {
        Ok(res) => (StatusCode::CREATED, Json(serde_json::json!({ "result": res }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn get_anomark_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "config": state.store.get_anomark_settings() }))
}

async fn get_anomark_availability(State(state): State<AppState>) -> Json<serde_json::Value> {
    let a = state.store.anomark_availability();
    Json(serde_json::json!({ "availability": a }))
}

async fn set_anomark_config(
    State(state): State<AppState>,
    Json(req): Json<AnoMarkSettings>,
) -> impl IntoResponse {
    match state.store.set_anomark_settings(req) {
        Ok(cfg) => (StatusCode::OK, Json(serde_json::json!({ "config": cfg }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn train_anomark(
    State(state): State<AppState>,
    Json(req): Json<AnoMarkTrainRequest>,
) -> impl IntoResponse {
    match state.store.train_anomark(req) {
        Ok(result) => (StatusCode::OK, Json(serde_json::json!({ "result": result }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn list_anomark_trains(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut trainings = state.store.list_anomark_trainings();
    trainings.reverse();
    Json(serde_json::json!({ "trainings": trainings }))
}

async fn download_anomark_model(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let Some(path) = state.store.anomark_train_stored_model_path(&id) else {
        return not_found("training job or model not found");
    };
    let data = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::to_value(ApiError {
                    error: e.to_string(),
                })
                .unwrap_or_default()),
            )
                .into_response();
        }
    };
    let name = format!("anomark-model-{}.bin", &id);
    file_download_response(
        &data,
        "application/octet-stream",
        &name,
    )
    .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e).into_response())
}

async fn download_anomark_training_data(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let Some(path) = state.store.anomark_train_stored_training_data_path(&id) else {
        return not_found("training job or data file not found");
    };
    let data = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    serde_json::to_value(ApiError {
                        error: e.to_string(),
                    })
                    .unwrap_or_default(),
                ),
            )
                .into_response();
        }
    };
    let name = format!("anomark-training-{}.jsonl", &id);
    file_download_response(
        &data,
        "application/x-ndjson",
        &name,
    )
    .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e).into_response())
}

fn not_found(msg: &str) -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::to_value(ApiError {
            error: msg.to_string(),
        })
        .unwrap_or_default()),
    )
        .into_response()
}

fn file_download_response(
    data: &[u8],
    content_type: &str,
    filename: &str,
) -> Result<axum::response::Response, String> {
    use axum::http::header::{HeaderName, HeaderValue};

    let cd = format!(r#"attachment; filename="{}""#, filename.replace('\"', ""));
    let disp = HeaderValue::from_str(&cd).map_err(|e| e.to_string())?;
    let ty = HeaderValue::from_str(content_type).map_err(|e| e.to_string())?;
    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderName::from_static("content-type"), ty)
        .header(HeaderName::from_static("content-disposition"), disp)
        .body(Body::from(data.to_vec()))
        .map_err(|e| e.to_string())
}

async fn get_run_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "config": state.store.get_run_config() }))
}

async fn set_run_config(
    State(state): State<AppState>,
    Json(req): Json<DetectionConfig>,
) -> impl IntoResponse {
    match state.store.set_run_config(req) {
        Ok(cfg) => (StatusCode::OK, Json(serde_json::json!({ "config": cfg }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn get_sigma_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "config": state.store.get_sigma_zero_settings() }))
}

async fn set_sigma_config(
    State(state): State<AppState>,
    Json(req): Json<SigmaZeroSettings>,
) -> impl IntoResponse {
    match state.store.set_sigma_zero_settings(req) {
        Ok(cfg) => (StatusCode::OK, Json(serde_json::json!({ "config": cfg }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn check_sigma_zero(
    State(state): State<AppState>,
    Json(req): Json<SigmaZeroCheckRequest>,
) -> impl IntoResponse {
    match state.store.check_sigma_zero(req) {
        Ok(result) => (StatusCode::OK, Json(serde_json::json!({ "result": result }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn get_run(Path(id): Path<String>, State(state): State<AppState>) -> impl IntoResponse {
    match state.store.get_run(&id) {
        Some(run) => (StatusCode::OK, Json(serde_json::json!({ "run": run }))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ApiError {
                error: "run not found".to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn get_run_detections(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.store.get_run(&id) {
        Some(run) => (
            StatusCode::OK,
            Json(serde_json::json!({ "findings": run.findings })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ApiError {
                error: "run not found".to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn get_honeycomb(
    Query(q): Query<HoneycombQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state
        .store
        .honeycomb_for_run_filtered(&q.run_id, q.min_score, q.severity.as_deref())
    {
        Some(cells) => (StatusCode::OK, Json(serde_json::json!({ "cells": cells }))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ApiError {
                error: "run not found".to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn upload_dataset(
    State(state): State<AppState>,
    Query(q): Query<UploadQuery>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut saved_paths: Vec<PathBuf> = Vec::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or_default().to_string();
        if name != "file" {
            continue;
        }
        let filename = field
            .file_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "upload.bin".to_string());
        let bytes = match field.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::to_value(ApiError {
                        error: format!("failed reading upload bytes: {}", e),
                    }).unwrap_or_default()),
                )
                    .into_response()
            }
        };
        let mut path = PathBuf::from(".ironsift-platform/uploads");
        if let Err(e) = std::fs::create_dir_all(&path) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::to_value(ApiError {
                    error: format!("failed creating upload dir: {}", e),
                }).unwrap_or_default()),
            )
                .into_response();
        }
        let safe_name = format!("{}-{}", uuid::Uuid::new_v4(), filename);
        path.push(safe_name);
        if let Err(e) = tokio::fs::write(&path, bytes).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::to_value(ApiError {
                    error: format!("failed writing upload: {}", e),
                }).unwrap_or_default()),
            )
                .into_response();
        }
        saved_paths.push(path);
    }

    if saved_paths.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: "missing file field".to_string(),
            }).unwrap_or_default()),
        )
            .into_response();
    }

    let tags: Vec<String> = q
        .tags
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut imported = Vec::new();
    for (idx, path) in saved_paths.iter().enumerate() {
        let name = if idx == 0 { q.name.clone() } else { None };
        match state
            .store
            .import_file_auto(path.to_str().unwrap_or_default(), name, tags.clone())
        {
            Ok(ds) => imported.push(ds),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::to_value(ApiError {
                        error: e.to_string(),
                    }).unwrap_or_default()),
                )
                    .into_response()
            }
        }
    }
    (StatusCode::CREATED, Json(serde_json::json!({ "datasets": imported }))).into_response()
}
