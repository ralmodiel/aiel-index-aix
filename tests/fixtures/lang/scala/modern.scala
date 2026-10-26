package demo

enum Color { case Red, Green }
case class User(name: String)
trait Repo { def find(id: Int): User }
class Service(repo: Repo) {
  def run(id: Int): String = repo.find(id).name
}
extension (s: String) def shout: String = s.toUpperCase
given Ordering[User] = Ordering.by(_.name)
object Main { def main(args: Array[String]): Unit = new Service(null).run(1) }
