package demo

import kotlin.jvm.JvmInline

sealed interface Shape
data class Circle(val r: Int) : Shape
data object Origin : Shape
@JvmInline value class Meters(val v: Double)
fun interface Greeter {
    fun greet(n: String): String
}
enum class Level {
    LOW, HIGH;
    companion object { fun parse(s: String) = valueOf(s) }
}

class Repo { fun find(id: Int): String = "x$id" }

class Service(private val repo: Repo) {
    suspend fun load(id: Int): String = repo.find(id)
    fun describe(s: Shape): String = when (s) {
        is Circle -> "circle ${s.r}"
        Origin -> "origin"
    }
}

fun main() {
    val svc = Service(Repo())
    svc.describe(Origin)
    val e = Level.entries
}
