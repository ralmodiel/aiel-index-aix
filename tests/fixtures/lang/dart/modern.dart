sealed class Shape {}
class Circle extends Shape { final int r; Circle(this.r); }
extension type Meters(double v) {}
class Service {
  final Repo repo;
  Service(this.repo);
  String load(int id) => repo.find(id);
}
class Repo { String find(int id) => '$id'; }
void main() { Service(Repo()).load(1); }
