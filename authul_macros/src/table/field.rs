//use heck::AsSnekCase;
//use pluralizer::pluralize;
use proc_macro2::{Ident, Span, TokenStream, TokenTree as Token};
use quote::quote;

use super::error;

#[derive(Clone, Debug)]
pub(super) struct Field {
	ident: Ident,
	ty: TokenStream,

	attrs: Attrs,
}

macro_rules! attr {
	($name:ident) => {
		pub(super) fn $name(&self) -> bool {
			self.attrs.$name
		}
	};
}

impl Field {
	pub(super) fn from(
		tokens: TokenStream,
		_field_span: Option<Span>,
	) -> Result<Self, TokenStream> {
		let mut tokens = tokens.into_iter().peekable();

		let (attrs, ident) = Attrs::from(&mut tokens)?;

		let Token::Ident(ident) = ident else {
			return error(
				&ident.span(),
				format!("unexpected token {ident:?} found (expected field name)"),
			);
		};

		let colon = tokens.next().expect("no punctuation after field ident");

		if let Token::Punct(ref p) = colon {
			if p.as_char() != ':' {
				return error(
					&colon.span(),
					"unexpected punctuation {colon:?} (expected ':')",
				);
			}
		} else {
			return error(
				&colon.span(),
				format!("unexpected token {colon:?} (expected ':')"),
			);
		}

		Ok(Field {
			ident,
			ty: tokens.collect(),
			attrs,
		})
	}

	attr!(find_by);
	attr!(find_all_by);
	attr!(belongs_to);
	attr!(has_many);
	attr!(read_accessor);
	attr!(take_accessor);
	attr!(with_accessor);
	attr!(set_accessor);
	attr!(update_accessor);

	fn virtual_field(&self) -> bool {
		self.has_many()
	}

	pub(super) fn relation_argument(&self) -> Option<TokenStream> {
		if self.attrs.belongs_to {
			let field_name = self.field_name();
			let field_type = &self.ty;

			Some(quote! { #field_name: #field_type })
		} else {
			None
		}
	}

	pub(super) fn relation_load(&self) -> TokenStream {
		if self.attrs.belongs_to {
			let field_name = self.field_name();
			let sql_field_name = format!("{field_name}_id");
			let field_type = &self.ty;

			quote! { let #field_name = #field_type::handle(self.conn.clone()).find(&row.get::<_, ::uuid::Uuid>(#sql_field_name)).await?; }
		} else {
			TokenStream::new()
		}
	}

	pub(super) fn relation_value(&self) -> Option<TokenStream> {
		if self.attrs.belongs_to {
			let field_name = self.field_name();

			Some(quote! { #field_name })
		} else {
			None
		}
	}

	pub(super) fn struct_field(&self) -> TokenStream {
		if self.virtual_field() {
			quote! {}
		} else {
			let field_name = self.field_name();
			let field_type = self.field_type();

			quote! { #field_name: #field_type, }
		}
	}

	pub(super) fn clone_field(&self) -> TokenStream {
		if self.virtual_field() {
			quote! {}
		} else {
			let field_name = self.field_name();

			quote! { #field_name: self.#field_name.clone() }
		}
	}

	pub(super) fn from_row_field(&self) -> TokenStream {
		let field_name = self.field_name();

		if self.attrs.belongs_to {
			quote! { #field_name, }
		} else if self.virtual_field() {
			quote! {}
		} else {
			let field_name_as_string = field_name.to_string();

			quote! { #field_name: row.get(#field_name_as_string), }
		}
	}

	pub(super) fn field_accessors(&self, vis: &TokenStream) -> TokenStream {
		let field_name = self.field_name();
		let field_type = &self.ty;

		let mut accessors = TokenStream::new();

		let getter = if self.read_accessor() {
			quote! {
				#vis fn #field_name(&self) -> &#field_type {
					&self.#field_name
				}
			}
		} else {
			quote! {}
		};

		if field_name == "id" {
			accessors.extend(getter);
		} else if self.attrs.belongs_to {
			accessors.extend(getter);
			let take_ident = Ident::new(
				&format!("take_{}", self.field_name()),
				self.field_name().span(),
			);
			let (setter_arg, setter_conversion) = self.setter_details();
			let update_ident = Ident::new(
				&format!("update_{}", self.field_name()),
				self.field_name().span(),
			);
			let sql_field_string = format!("{}_id", self.field_name());

			if self.take_accessor() {
				accessors.extend(quote! {
					#vis fn #take_ident(self) -> #field_type {
						self.#field_name
					}
				});
			}

			if self.update_accessor() {
				accessors.extend(quote! {
					#vis fn #update_ident(&mut self, #setter_arg) -> &Self {
						self.#field_name = #setter_conversion;
						self.__updated_fields.insert(#sql_field_string, Box::new(self.#field_name.id().clone()));

						self
					}
				});
			}
		} else if self.has_many() {
			if self.read_accessor() {
				accessors.extend(quote! {
					#vis async fn #field_name<C: ::deadpool_postgres::GenericClient>(&self, db: crate::Conn<C>) -> Result<Vec<#field_type>, crate::Error> {
						let sql = format!(r#"SELECT {} FROM {} WHERE {} = $1"#, #field_type::fields().iter().map(|f| crate::quote::identifier(f)).collect::<Vec<_>>().join(","), crate::quote::identifier(#field_type::table_name()), crate::quote::identifier(Self::belongs_to_field_name()));
						tracing::debug!(sql);

						let stmt = db.prepare_cached(&sql).await?;
						Ok(db.query(&stmt, &[&self.id()]).await?.into_iter().map(|row| Ok(#field_type::from_row(&row, self.clone())?)).collect::<Result<Vec<_>, crate::Error>>()?)
					}
				});
			}
		} else {
			accessors.extend(getter);

			let (setter_arg, setter_conversion) = self.setter_details();
			let update_ident = Ident::new(
				&format!("update_{}", self.field_name()),
				self.field_name().span(),
			);
			let field_name = self.field_name();
			let field_name_string = self.field_name().to_string();

			if self.update_accessor() {
				accessors.extend(quote! {
					#vis fn #update_ident(&mut self, #setter_arg) -> &Self {
						let val = #setter_conversion;
						self.#field_name = val.clone();
						self.__updated_fields.insert(#field_name_string, Box::new(val));

						self
					}
				});
			}
		}

		accessors
	}

	pub(super) fn new_inner_field(&self) -> TokenStream {
		if self.is_id() {
			quote! { id: ::uuid::Uuid, }
		} else if self.virtual_field() {
			quote! {}
		} else {
			let field_name = self.field_name();
			let field_type = &self.ty;

			quote! { #field_name: Option<#field_type>, }
		}
	}

	pub(super) fn new_inner_field_default(&self) -> TokenStream {
		if self.is_id() {
			if self.attrs.v4_uuid {
				quote! { id: ::uuid::Uuid::new_v4(), }
			} else {
				quote! { id: ::uuid::Uuid::now_v7(), }
			}
		} else if self.virtual_field() {
			quote! {}
		} else {
			let field_name = self.field_name();

			quote! { #field_name: None, }
		}
	}

	pub(super) fn set_field_default(&self) -> TokenStream {
		if self.is_id() {
			TokenStream::new()
		} else if self.attrs.default.is_empty() {
			TokenStream::new()
		} else {
			let field_name = self.field_name();
			let d = &self.attrs.default;
			quote! { self.#field_name = Some(#d); }
		}
	}

	pub(super) fn new_impl_methods(&self, vis: &TokenStream) -> TokenStream {
		if self.is_id() {
			TokenStream::new()
		} else {
			let mut accessors = TokenStream::new();

			let field_name = self.field_name();

			let (setter_arg, setter_conversion) = self.setter_details();
			let with_ident = Ident::new(&format!("with_{}", &field_name), self.field_name().span());
			let set_ident = Ident::new(&format!("set_{}", &field_name), self.field_name().span());

			if self.virtual_field() {
				// We'll stub these out, and make them if/when I actually ever call them
				if self.with_accessor() {
					accessors.extend(quote! {
						#[must_use]
						#vis fn #with_ident(mut self, #setter_arg) -> Self {
							todo!()
						}
					});
				}

				if self.set_accessor() {
					accessors.extend(quote! {
						#vis fn #set_ident(&mut self, #setter_arg) {
							todo!()
						}
					});
				}
			} else {
				if self.with_accessor() {
					accessors.extend(quote! {
						#[must_use]
						#vis fn #with_ident(mut self, #setter_arg) -> Self {
							self.inner.#field_name = Some(#setter_conversion);
							self
						}
					});
				}

				if self.set_accessor() {
					accessors.extend(quote! {
						#vis fn #set_ident(&mut self, #setter_arg) {
							self.inner.#field_name = Some(#setter_conversion);
						}
					});
				}
			}

			accessors
		}
	}

	pub(super) fn find_by_builder_method(&self, vis: &TokenStream) -> TokenStream {
		// Will this work out long term?  Who knows!
		self.new_impl_methods(vis)
	}

	pub(super) fn create_query_value(&self) -> TokenStream {
		let field_name = self.field_name();

		if self.attrs.belongs_to {
			quote! { &self.inner.#field_name.as_ref().map(|f| f.id()) }
		} else if self.virtual_field() {
			quote! {}
		} else {
			quote! { &self.inner.#field_name }
		}
	}

	pub(super) fn sql_field_name(&self) -> Option<String> {
		if self.belongs_to() {
			Some(format!("{}_id", self.field_name()))
		} else if self.virtual_field() {
			None
		} else {
			Some(self.field_name().to_string())
		}
	}

	pub(super) fn is_id(&self) -> bool {
		self.field_name().to_string() == "id"
	}

	pub(super) fn field_name(&self) -> &Ident {
		&self.ident
	}

	pub(super) fn field_type(&self) -> &TokenStream {
		&self.ty
	}

	pub(super) fn setter_details(&self) -> (TokenStream, TokenStream) {
		let tokens = self.ty.clone().into_iter().collect::<Vec<_>>();

		if tokens[0].to_string() == "Vec" {
			if tokens[1].to_string() == "<" && tokens[3].to_string() == ">" {
				if tokens[2].to_string() == "u8" {
					// Vec<u8> is... speshul
					(quote! { v: impl Into<Vec<u8>> }, quote! { v.into() })
				} else {
					let type_arg = &tokens[2];
					(
						quote! { v: impl IntoIterator<Item = impl Into<#type_arg>> },
						quote! { v.into_iter().map(|i| i.into()).collect::<Vec<_>>() },
					)
				}
			} else {
				panic!("Vec without type parameter");
			}
		} else {
			let t = &self.ty;
			(quote! { v: impl Into<#t> }, quote! { v.into() })
		}
	}
}

#[derive(Clone, Debug)]
struct Attrs {
	belongs_to: bool,
	default: TokenStream,
	find_by: bool,
	find_all_by: bool,
	has_many: bool,
	v4_uuid: bool,

	read_accessor: bool,
	take_accessor: bool,
	with_accessor: bool,
	set_accessor: bool,
	update_accessor: bool,
}

impl Attrs {
	fn from<I>(tokens: &mut I) -> Result<(Self, Token), TokenStream>
	where
		I: Iterator<Item = Token>,
	{
		let mut attrs = Attrs {
			belongs_to: false,
			default: TokenStream::new(),
			find_by: false,
			find_all_by: false,
			has_many: false,
			v4_uuid: false,

			read_accessor: true,
			take_accessor: true,
			with_accessor: true,
			set_accessor: true,
			update_accessor: true,
		};

		while let Some(t) = tokens.next() {
			if let Token::Ident(_) = t {
				return Ok((attrs, t));
			}

			if let Token::Punct(ref p) = t {
				if p.as_char() != '#' {
					return error(
						&t.span(),
						"expected field name or outer attribute definition",
					);
				}
			}

			let Some(Token::Group(g)) = tokens.next() else {
				panic!("how did we manage to define an attr without a group?!?");
			};

			let mut attr_tokens = g.stream().into_iter();

			if let Some(t) = attr_tokens.next() {
				if let Token::Ident(ref i) = t {
					if i.to_string() == "column" {
						if let Some(Token::Group(g)) = attr_tokens.next() {
							attrs.parse_column_options(g.stream())?;
						} else {
							return error(
								&t.span(),
								"expected a collection of column options (eg #[column(find_all)])",
							);
						}
					} else if i.to_string() == "relation" {
						if let Some(Token::Group(g)) = attr_tokens.next() {
							attrs.parse_relation_options(g.stream())?;
						} else {
							return error(&t.span(), "expected a collection of relation options (eg #[relation(belongs_to)])");
						}
					} else {
						return error(
							&t.span(),
							"expected either a 'column' or 'relation' attribute",
						);
					}
				} else {
					return error(
						&t.span(),
						"expected either a 'column' or 'relation' attribute",
					);
				}
			}
		}

		panic!("CAN'T HAPPEN: parsed field tokens without coming across an identifier");
	}

	fn parse_column_options(&mut self, tokens: TokenStream) -> Result<(), TokenStream> {
		let mut tokens = tokens.into_iter();

		while let Some(t) = tokens.next() {
			if let Token::Ident(ref i) = t {
				match i.to_string().as_str() {
					"default" => {
						if let Some(Token::Group(g)) = tokens.next() {
							self.default = g.stream()
						} else {
							return error(&t.span(), "expected a default value expression (eg #[column(default((42 + 420).to_string()))])");
						}
					}
					"find_by" => self.find_by = true,
					"find_all_by" => self.find_all_by = true,
					"v4_uuid" => self.v4_uuid = true,
					"accessors" => {
						if let Some(Token::Group(g)) = tokens.next() {
							self.parse_accessors(g.stream())?;
						} else {
							return error(
								&t.span(),
								"expected a list of accessors (eg #[column(accessors(read,take))])",
							);
						}
					}
					_ => return error(&t.span(), "unrecognised column option"),
				}
			} else {
				return error(&t.span(), "malformed column options (expected identifier)");
			}
		}

		Ok(())
	}

	fn parse_accessors(&mut self, tokens: TokenStream) -> Result<(), TokenStream> {
		// Once an accessors attribute is found, it's opt-in, rather than opt-out
		self.read_accessor = false;
		self.take_accessor = false;
		self.with_accessor = false;
		self.set_accessor = false;
		self.update_accessor = false;

		let mut tokens = tokens.into_iter();

		while let Some(t) = tokens.next() {
			match t {
				Token::Ident(ref i) => match i.to_string().as_str() {
					"read" => self.read_accessor = true,
					"take" => self.take_accessor = true,
					"with" => self.with_accessor = true,
					"set" => self.set_accessor = true,
					"update" => self.update_accessor = true,
					_ => return error(&t.span(), "unrecognised accessor name (valid names are 'read', 'take', 'with', 'set', and 'update')"),
				},
				Token::Punct(ref p) => if p.as_char() != ',' {
					return error(&t.span(), "invalid character in accessor list (expected comma-separated list of names)");
				},
				_ => return error(&t.span(), "invalid character in accessor list (expected comma-separated list of names)"),
			}
		}

		Ok(())
	}

	fn parse_relation_options(&mut self, tokens: TokenStream) -> Result<(), TokenStream> {
		let mut tokens = tokens.into_iter();

		while let Some(t) = tokens.next() {
			if let Token::Ident(ref i) = t {
				match i.to_string().as_str() {
					"belongs_to" => self.belongs_to = true,
					"has_many" => self.has_many = true,
					_ => return error(&t.span(), "unrecognised column option"),
				}
			} else {
				return error(&t.span(), "malformed column options (expected identifier)");
			}
		}

		Ok(())
	}
}
