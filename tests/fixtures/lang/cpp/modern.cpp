#include <vector>
namespace demo {
template <typename T> class Stack {
 public:
  void push(const T& v) { items.push_back(v); log(); }
 private:
  void log();
  std::vector<T> items;
};
template <typename T> void Stack<T>::log() {}
auto twice = [](auto x) { return x * 2; };
}
int main() { demo::Stack<int> s; s.push(1); }
