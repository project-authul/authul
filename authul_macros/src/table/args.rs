use proc_macro2::{Ident, Spacing, Span, TokenStream, TokenTree as Token};
use quote::{quote, quote_spanned};

#[derive(Clone, Debug, Default)]
pub(crate) struct Args {
	pub(super) table_name: Option<String>,
	pub(super) has_many: Vec<(Ident, Ident)>,
}

impl Args {
	pub(crate) fn from(tokens: TokenStream) -> Result<Self, TokenStream> {
		let mut tokens = tokens.into_iter();
		let mut args = Self::default();

		while let Some(t) = tokens.next() {
			if let Token::Ident(ref ident) = t {
				let ident = ident.to_string();

				match ident.as_str() {
					"name" => args.table_name = Some(Self::parse_name(&mut tokens)?),
					"has_many" => {
						if let Some(Token::Group(g)) = tokens.next() {
							args.has_many
								.push(Self::parse_has_many(g.stream(), g.span())?);
						} else {
							return Err(quote_spanned! { t.span()=>
								compile_error!("invalid argument to has_many; expected (<ident>)");
							});
						}
					}
					_ => {
						return Err(quote_spanned! {
							t.span() => compile_error!("invalid macro arg; expected 'name' or 'has_many'");
						})
					}
				}
			} else {
				return Err(quote_spanned! {
					t.span() => compile_error!("expected ident");
				});
			}
		}

		Ok(args)
	}

	fn parse_name(tokens: &mut impl Iterator<Item = Token>) -> Result<String, TokenStream> {
		let Some(t) = tokens.next() else {
			return Err(
				quote! { compile_error!("premature end of macro arguments; expected '=' after 'name'"); },
			);
		};

		if let Token::Punct(ref p) = t {
			if p.as_char() != '=' || p.spacing() != Spacing::Alone {
				return Err(quote_spanned! {
					t.span() => compile_error!("expected '='");
				});
			}
		} else {
			return Err(quote_spanned! {
				t.span() => compile_error!("expected '='");
			});
		}

		let Some(t) = tokens.next() else {
			return Err(quote! { compile_error!("expected ident"); });
		};

		if let Token::Literal(ref lit) = t {
			let s = lit.to_string();

			if let Some(s) = s.strip_prefix('"').map_or(None, |s| s.strip_suffix('"')) {
				Ok(s.to_string())
			} else {
				Err(quote_spanned! {
					t.span() => compile_error!("expected string");
				})
			}
		} else {
			Err(quote_spanned! {
				t.span() => compile_error!("expected string");
			})
		}
	}
	fn parse_has_many(_tokens: TokenStream, _span: Span) -> Result<(Ident, Ident), TokenStream> {
		todo!()
		/*
		let mut tokens = tokens.into_iter();

		let (maybe_t, overflow) = (tokens.next(), tokens.next());

		if let Some(t) = overflow {
			return Err(quote_spanned! { t.span()=>
				compile_error!("unexpected token; has_many() only accepts a single ident as an argument");
			})
		}

		let Some(t) = maybe_t else {
			return Err(quote_spanned! { span=>
				compile_error!("missing ident arg to has_many");
			})
		};

		if let Token::Ident(ident) = t {

			Ok((ident, )
		} else {
			Err(quote_spanned! { t.span()=>
				compile_error!("unexpected argument to has_many(); expected ident");
			})
		}
		*/
	}
}
