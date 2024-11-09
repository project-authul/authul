#[authul_macros::return_as_is]
enum Blargh {}

#[authul_macros::authul_table]
enum Foo {}

#[authul_macros::authul_table]
fn foo() {}

#[authul_macros::authul_table]
struct Bar;

#[authul_macros::authul_table]
struct Baz(String);

fn main() {
}
