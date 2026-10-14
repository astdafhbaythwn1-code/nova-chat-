// Optional C++ reference module for a future native service.
// This is a local app ledger example, not real-money currency or a payment processor.
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

class StarsWallet {
 public:
  explicit StarsWallet(std::uint64_t starting = 0) : balance_(starting) {}
  std::uint64_t balance() const { return balance_; }

  void add(std::uint64_t amount) {
    if (amount > std::numeric_limits<std::uint64_t>::max() - balance_)
      throw std::overflow_error("star balance overflow");
    balance_ += amount;
  }

  void spend(std::uint64_t amount) {
    if (amount > balance_) throw std::runtime_error("not enough stars");
    balance_ -= amount;
  }

 private:
  std::uint64_t balance_;
};

int main() {
  StarsWallet demo(20);
  demo.add(10);
  demo.spend(5);
  std::cout << "Demo star balance: " << demo.balance() << "\\n";
  return 0;
}
