#[authul_macros::authul_table(name = 42)]
struct Foo;

#[authul_macros::authul_table(name = ())]
struct Bar;

#[authul_macros::authul_table(name = bob)]
struct Baz;

fn main() {
}
