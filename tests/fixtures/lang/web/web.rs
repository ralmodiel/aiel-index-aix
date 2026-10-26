use actix_web::{get, post, web, App};
#[get("/users/{id}")]
async fn user(id: web::Path<u32>) -> String { String::new() }
#[post("/users")]
async fn create() {}
fn cfg(c: &mut web::ServiceConfig) {
    c.service(web::scope("/api").service(user).route("/ping", web::get().to(ping)));
}
async fn ping() {}
fn axum_app() -> Router {
    Router::new().route("/items", get(list).post(add)).nest("/v2", Router::new().route("/x", get(x)))
}
#[get("/rocket/<name>")]
fn hello(name: &str) {}
fn r() { rocket::build().mount("/base", routes![hello]); }
