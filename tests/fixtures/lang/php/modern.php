<?php
declare(strict_types=1);

namespace Demo;

#[\Attribute]
final class Route { public function __construct(public string $path = '/') {} }

enum Status: string implements HasLabel
{
    case Active = 'a';
    case Off = 'o';
    public function label(): string { return ucfirst($this->value); }
    public static function default(): self { return self::Active; }
}

interface HasLabel { public function label(): string; }

readonly class Money
{
    public function __construct(public int $amount, private Currency $cur = new Currency('USD')) {}
    public function add(Money $o): static { return new static($this->amount + $o->amount); }
}

class Currency { public function __construct(public string $code) {} }

final class Service
{
    #[Route('/x')]
    public function run(int|string $id): never
    {
        $f = strlen(...);
        $m = new Money(1);
        $m->add($m);
        self::boot();
        throw new \Exception('x');
    }
    private static function boot(): void {}
}
