package app
import io.ktor.server.routing.*
fun Route.api() {
    route("/api") {
        get("/users") { call.respond(1) }
        authenticate("jwt") {
            post("/users/{id}") { }
        }
    }
    get("/") { }
}
