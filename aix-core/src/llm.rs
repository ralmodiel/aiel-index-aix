//! Minimal OpenAI-compatible client for the local AI harness: `/v1/embeddings` and `/v1/chat/completions`.
//! Every call has a hard timeout; callers treat errors as "unavailable" and carry on.

use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::config::Endpoint;

fn agent(timeout: Duration) -> ureq::Agent {
    let cfg = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .timeout_connect(Some(Duration::from_millis(800)))
        .max_redirects(0) // a local server must not bounce document text elsewhere
        .build();
    ureq::Agent::new_with_config(cfg)
}

fn url(base: &str, path: &str) -> String {
    let b = base.trim_end_matches('/');
    let b = b.strip_suffix("/v1").unwrap_or(b);
    format!("{b}{path}")
}

/// Embed `texts`; returns L2-normalised vectors in input order.
pub fn embed(ep: &Endpoint, texts: &[String], timeout: Duration) -> Result<Vec<Vec<f32>>> {
    crate::config::check_loopback(&ep.url).map_err(|m| anyhow!("{m}"))?;
    let model = if ep.model.is_empty() { "local" } else { &ep.model };
    let mut resp =
        agent(timeout).post(&url(&ep.url, "/v1/embeddings")).send_json(json!({ "model": model, "input": texts }))?;
    let v: Value = resp.body_mut().with_config().limit(64 << 20).read_json()?;
    let mut data: Vec<(usize, Vec<f32>)> = v["data"]
        .as_array()
        .ok_or_else(|| anyhow!("no data in embeddings response"))?
        .iter()
        .map(|d| {
            let idx = d["index"].as_u64().unwrap_or(0) as usize;
            let e: Vec<f32> = d["embedding"]
                .as_array()
                .map(|a| a.iter().map(|x| x.as_f64().unwrap_or(0.0) as f32).collect())
                .unwrap_or_default();
            (idx, e)
        })
        .collect();
    if data.len() != texts.len() {
        return Err(anyhow!("embeddings: got {} vectors for {} texts", data.len(), texts.len()));
    }
    data.sort_by_key(|d| d.0);
    Ok(data.into_iter().map(|(_, v)| normalize(v)).collect())
}

pub fn normalize(mut v: Vec<f32>) -> Vec<f32> {
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt() + 1e-9;
    v.iter_mut().for_each(|x| *x /= n);
    v
}

/// One chat completion; returns the assistant text.
pub fn chat(ep: &Endpoint, system: &str, user: &str, max_tokens: u32, timeout: Duration) -> Result<String> {
    crate::config::check_loopback(&ep.url).map_err(|m| anyhow!("{m}"))?;
    let model = if ep.model.is_empty() { "local" } else { &ep.model };
    let body = json!({
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "max_tokens": max_tokens,
        "temperature": 0.1,
        // llama.cpp / vLLM: skip hidden reasoning for these short tasks
        "chat_template_kwargs": {"enable_thinking": false},
    });
    let mut resp = agent(timeout).post(&url(&ep.url, "/v1/chat/completions")).send_json(body)?;
    let v: Value = resp.body_mut().read_json()?;
    let t = v["choices"][0]["message"]["content"].as_str().unwrap_or("").trim().to_string();
    // strip any <think> block a reasoning model still emits
    let t = match t.rfind("</think>") {
        Some(i) => t[i + 8..].trim().to_string(),
        None => t,
    };
    if t.is_empty() {
        return Err(anyhow!("empty completion"));
    }
    Ok(t)
}

pub fn to_blob(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

pub fn from_blob(b: &[u8]) -> Vec<f32> {
    b.as_chunks::<4>().0.iter().map(|c| f32::from_le_bytes(*c)).collect()
}

pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}
