mod table;

use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn authul_table(args: TokenStream, input: TokenStream) -> TokenStream {
	let args = match table::Args::from(args.into()) {
		Ok(v) => v,
		Err(e) => return e.into(),
	};

	let table = match table::Struct::from(input.into(), args) {
		Ok(v) => v,
		Err(e) => return e.into(),
	};

	table.to_tokens().into()
}

#[proc_macro_attribute]
pub fn return_as_is(_attr: TokenStream, item: TokenStream) -> TokenStream {
	item
}
