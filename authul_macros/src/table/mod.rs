mod args;
mod field;

pub(super) use args::Args;
use field::Field;

use heck::AsSnekCase;
use pluralizer::pluralize;
use proc_macro2::{Delimiter, Ident, Span, TokenStream, TokenTree as Token};
use quote::{quote, quote_spanned, ToTokens as _};

#[derive(Clone, Debug)]
pub(crate) struct Struct {
	attrs: TokenStream,
	vis: TokenStream,
	ident: Ident,
	table_name: String,
	fields: Vec<Field>,
}

impl Struct {
	pub(crate) fn from(tokens: TokenStream, args: Args) -> Result<Self, TokenStream> {
		let mut tokens = tokens.into_iter();

		let mut t = tokens.next().expect("macro called without item");

		let mut attrs = TokenStream::new();

		// Just shunt all other outer attrs into storage for later inclusion
		// This works because attrs are Punct('#') followed by Group(delimiter='[')
		while !matches!(t, Token::Ident(_)) {
			t.to_tokens(&mut attrs);
			t = tokens
				.next()
				.expect("consumed entire attr_macro stream without finding a single ident");
		}

		let (vis, t) = if let Token::Ident(ref ident) = t {
			if ident.to_string() == "pub" {
				let mut vis = TokenStream::new();
				vis.extend([t]);
				let t = tokens.next().expect("nothing after 'pub', WTF?");
				if let Token::Group(_) = t {
					vis.extend([t]);
					(vis, tokens.next().expect("nothing after visibility, WTF?"))
				} else {
					(vis, t)
				}
			} else {
				(TokenStream::new(), t)
			}
		} else {
			panic!(
				"CAN'T HAPPEN: macro called on non-item {t:?}, rest of the stream is: {:#?}",
				tokens.collect::<Vec<_>>()
			);
		};

		if let Token::Ident(ref kind) = t {
			if kind.to_string() != "struct" {
				return error(&t.span(), "authul_table only applies to structs");
			}
		}

		let t = tokens
			.next()
			.expect("I've been through the compiler on a struct with no name");

		let Token::Ident(struct_name) = t else {
			return error(
				&t.span(),
				"struct name isn't an ident.  I'm not even mad; that's amazing!",
			);
		};

		let t = tokens.next().expect("nothing after struct name");

		let Token::Group(fields_group) = t.clone() else {
			return error(
				&t.span(),
				format!("authul_table only works on structs with named fields"),
			);
		};

		if fields_group.delimiter() != Delimiter::Brace {
			return error(
				&t.span(),
				"authul_table only works on structs with named fields",
			);
		}

		let tokens = fields_group.stream().into_iter();

		let mut result = Struct {
			attrs,
			vis,
			table_name: args.table_name.unwrap_or_else(|| {
				pluralize(&AsSnekCase(struct_name.to_string()).to_string(), 2, false)
			}),
			ident: struct_name,
			fields: Vec::new(),
		};

		let mut field_stream = TokenStream::new();
		let mut field_span: Option<Span> = None;

		for t in tokens {
			if let Token::Ident(ref i) = t {
				if field_span.is_none() {
					field_span = Some(i.span().clone());
				}
			}
			if let Token::Punct(ref p) = t {
				if p.as_char() == ',' {
					result.fields.push(Field::from(field_stream, field_span)?);
					field_stream = TokenStream::new();
				} else {
					field_stream.extend([t]);
				}
			} else {
				field_stream.extend([t]);
			}
		}

		if !field_stream.is_empty() {
			// Just in case we're parsing a struct created by a monster who doesn't put commas
			// after the last field
			result.fields.push(Field::from(field_stream, field_span)?);
		}

		Ok(result)
	}

	pub(crate) fn to_tokens(&self) -> TokenStream {
		let mut tokens = TokenStream::new();

		let attrs = &self.attrs;
		let struct_name = &self.ident;
		let vis = &self.vis;

		let table_name = &self.table_name;

		let mut struct_fields = TokenStream::new();
		let mut clone_fields = Vec::<TokenStream>::new();
		let mut relation_arguments: Vec<TokenStream> = Vec::new();
		let mut relation_loads = TokenStream::new();
		let mut relation_values: Vec<TokenStream> = Vec::new();
		let mut relation_values_from_inner: Vec<TokenStream> = Vec::new();
		let mut from_row_fields = TokenStream::new();
		let mut field_accessors = TokenStream::new();
		let mut new_inner_fields = TokenStream::new();
		let mut new_inner_field_defaults = TokenStream::new();
		let mut set_field_defaults = Vec::<TokenStream>::new();
		let mut new_impl_methods = TokenStream::new();
		let mut find_by_builder_methods = Vec::<TokenStream>::new();

		let mut create_query_values: Vec<TokenStream> = Vec::new();

		let mut sql_fields = Vec::new();
		let mut value_placeholders = Vec::new();

		struct_fields.extend(quote! { __updated_fields: ::std::collections::HashMap<&'static str, Box<dyn ::tokio_postgres::types::ToSql + Sync>>, });
		clone_fields.push(quote! { __updated_fields: ::std::collections::HashMap::new() });
		from_row_fields.extend(quote! { __updated_fields: ::std::collections::HashMap::new(), });

		#[allow(clippy::expect_used)] // Ensured by darling(supports(struct_named))
		for (i, f) in self.fields.iter().enumerate() {
			if let Some(arg) = f.relation_argument() {
				relation_arguments.push(arg);
			}
			relation_loads.extend(f.relation_load());
			if let Some(arg) = f.relation_value() {
				relation_values.push(arg.clone());
				relation_values_from_inner
					.push(quote! { self.inner.#arg.expect("related struct to be set") });
			}

			struct_fields.extend(f.struct_field());
			clone_fields.push(f.clone_field());
			from_row_fields.extend(f.from_row_field());
			field_accessors.extend(f.field_accessors(&self.vis));
			new_inner_fields.extend(f.new_inner_field());
			new_inner_field_defaults.extend(f.new_inner_field_default());
			set_field_defaults.push(f.set_field_default());
			new_impl_methods.extend(f.new_impl_methods(&self.vis));
			create_query_values.push(f.create_query_value());
			find_by_builder_methods.push(f.find_by_builder_method(&self.vis));

			if let Some(sql_field_name) = f.sql_field_name() {
				sql_fields.push(sql_field_name);
				value_placeholders.push(format!("${}", i + 1));
			}
		}

		let select_query_root = format!("SELECT {} FROM {table_name}", sql_fields.join(","));
		let mut find_by_methods = TokenStream::new();

		// This is a separate loop because creating the queries requires the full list of
		// fields, which is only available after all the fields have been walked
		#[allow(clippy::expect_used)] // Ensured by darling(supports(struct_named))
		for f in &self.fields {
			#[allow(clippy::expect_used)] // Ensured by darling(supports(struct_named))
			let field_name = f.field_name();
			let field_name_as_string = field_name.to_string();
			let field_type = f.field_type();

			if f.find_by() {
				let fn_ident = Ident::new(
					&format!("find_by_{field_name_as_string}"),
					f.field_name().span(),
				);
				let query = format!("{select_query_root} WHERE {field_name} = $1");

				let val_type = if field_type.to_token_stream().to_string() == "String" {
					quote! { impl AsRef<str> + std::fmt::Display + std::fmt::Debug }
				} else {
					quote! { impl AsRef<#field_type> + std::fmt::Display + std::fmt::Debug }
				};

				find_by_methods.extend(quote! {
					pub async fn #fn_ident(&self, v: #val_type) -> Result<#struct_name, crate::Error> {
						tracing::debug!(value=v.to_string(), sql=#query);
						let stmt = self.conn.prepare_cached(#query).await?;

						#relation_loads

						#struct_name::from_row(self.conn.query(&stmt, &[&v.as_ref()]).await?.get(0).ok_or(crate::Error::not_found(#table_name, #field_name_as_string, v.as_ref()))?, #(#relation_values),*)
					}
				});
			}

			if f.find_all_by() || f.belongs_to() {
				let fn_ident = Ident::new(
					&format!("find_all_by_{field_name_as_string}"),
					f.field_name().span(),
				);
				let query = if f.belongs_to() {
					format!("{select_query_root} WHERE {field_name}_id = $1")
				} else {
					format!("{select_query_root} WHERE {field_name} = $1")
				};

				let (val_type, val_fetch, referent) =
					if field_type.to_token_stream().to_string() == "String" {
						(
							quote! { impl AsRef<str> + std::fmt::Debug + Clone },
							quote! { v.as_ref() },
							quote! {},
						)
					} else if f.belongs_to() {
						(
							quote! { &#field_type },
							quote! { v.id() },
							quote! { v.clone() },
						)
					} else {
						(quote! { &#field_type }, quote! { v }, quote! {})
					};

				find_by_methods.extend(quote! {
					#[tracing::instrument(level = "debug", skip(self))]
					pub async fn #fn_ident(&self, v: #val_type) -> Result<Vec<#struct_name>, crate::Error> {
						let value = #val_fetch;

						tracing::debug!(?value, sql=#query);
						let stmt = self.conn.prepare_cached(#query).await?;

						Ok(self.conn.query(&stmt, &[&value]).await?.into_iter().map(|row| #struct_name::from_row(&row, #referent)).collect::<Result<Vec<_>, _>>()?)
					}
				});
			}
		}

		let create_query = format!("WITH new_record AS (INSERT INTO {table_name} ({sql_fields}) VALUES ({value_placeholders}) RETURNING {sql_fields}) SELECT {sql_fields} FROM new_record", sql_fields=sql_fields.join(","), value_placeholders=value_placeholders.join(","));
		let find_query = format!("{select_query_root} WHERE id=$1");
		let update_query = format!("UPDATE {table_name} SET {{fields}} WHERE id=$1");

		let from_composite_type = if relation_arguments.is_empty() {
			quote! {
				#vis fn from_composite_type(row: &::tokio_postgres::CompositeType) -> Result<Self, crate::Error> {
					Ok(
						Self {
							#from_row_fields
						}
					)
				}
			}
		} else {
			quote! {}
		};

		let module_name = Ident::new(&pluralize(&self.table_name, 1, false), Span::call_site());
		let belongs_to_field_name = format!("{module_name}_id");

		tokens.extend(quote! {
			#attrs
			#vis struct #struct_name {
				#struct_fields
			}

			#[automatically_derived]
			impl #struct_name {
				#vis fn from_row(row: &::tokio_postgres::Row, #(#relation_arguments),*) -> Result<Self, crate::Error> {
					Ok(
						Self {
							#from_row_fields
						}
					)
				}

				#from_composite_type

				#vis fn handle<C: ::deadpool_postgres::GenericClient>(conn: crate::Conn<C>) -> Handle<C> {
					Handle { conn }
				}

				pub(crate) fn table_name() -> &'static str {
					#table_name
				}

				pub(crate) fn fields() -> Vec<&'static str> {
					vec![#(#sql_fields),*]
				}

				pub(crate) fn belongs_to_field_name() -> &'static str {
					#belongs_to_field_name
				}

				#[tracing::instrument(level = "debug", skip(db))]
				#vis async fn save<C: ::deadpool_postgres::GenericClient>(&self, db: &Handle<C>) -> Result<(), crate::Error> {
					if self.__updated_fields.is_empty() {
						// That was easy
						return Ok(());
					}

					let mut values: Vec<&(dyn ::tokio_postgres::types::ToSql + Sync)> = Vec::new();
					values.push(&self.id);
					let mut fields = String::new();

					for (i, (n, v)) in self.__updated_fields.iter().enumerate() {
						values.push(v.as_ref());
						if i > 0 {
							fields.push(',');
						}
						fields.push_str(&format!("{n}=${}", i + 2));
					}

					let sql = format!(#update_query);
					tracing::debug!(sql);
					let stmt = db.conn.prepare_cached(&sql).await?;
					db.conn.execute(&stmt, &values).await?;
					Ok(())
				}

				#field_accessors
			}

			#[automatically_derived]
			impl Clone for #struct_name {
				fn clone(&self) -> Self {
					Self {
						#(#clone_fields),*
					}
				}
			}

			#[automatically_derived]
			impl crate::Pool {
				/// Get a database connection to work with records from this table
				pub async fn #module_name(&self) -> Result<crate::model::#module_name::Handle<::deadpool_postgres::Object>, crate::Error> {
					Ok(crate::model::#module_name::#struct_name::handle(self.conn().await?))
				}
			}

			#[automatically_derived]
			impl<C: ::deadpool_postgres::GenericClient> crate::Conn<C> {
				/// Get a database connection to work with records from this table
				pub fn #module_name(&self) -> crate::model::#module_name::Handle<C> {
					crate::model::#module_name::#struct_name::handle(self.clone())
				}
			}

			#[automatically_derived]
			impl crate::DatabaseRecord for #struct_name {
				fn id(&self) -> &::uuid::Uuid {
					&self.id
				}

				fn table_name(&self) -> String {
					#table_name.to_string()
				}
			}

			impl crate::DeleteRecord for #struct_name {}

			#[derive(Debug)]
			struct NewInner {
				#new_inner_fields
			}

			#[automatically_derived]
			impl Default for NewInner {
				fn default() -> Self {
					Self {
						#new_inner_field_defaults
					}
				}
			}

			impl NewInner {
				fn set_field_defaults(mut self) -> Self {
					#(#set_field_defaults);*
					self
				}
			}

			#[derive(Debug)]
			#vis struct New<C: ::deadpool_postgres::GenericClient> {
				conn: crate::Conn<C>,
				inner: NewInner,
			}

			#[automatically_derived]
			impl<C: ::deadpool_postgres::GenericClient> New<C> {
				#new_impl_methods

				#[tracing::instrument(level = "debug", skip(self))]
				#vis async fn save(self) -> Result<#struct_name, crate::Error> {
					tracing::debug!(sql=#create_query);
					let stmt = self.conn.prepare_cached(#create_query).await?;
					#struct_name::from_row(self.conn.query(&stmt, &[#(#create_query_values),*]).await?.get(0).ok_or(crate::Error::not_found(#table_name, "id", self.inner.id))?, #(#relation_values_from_inner),*)
				}
			}

			#[derive(Debug)]
			#vis struct Handle<C: ::deadpool_postgres::GenericClient> {
				conn: crate::Conn<C>,
			}

			pub type ConnHandle = Handle<::deadpool_postgres::Client>;

			#[automatically_derived]
			impl<C: ::deadpool_postgres::GenericClient> Handle<C> {
				#vis fn new(&self) -> New<C> {
					New { conn: self.conn.clone(), inner: NewInner::default().set_field_defaults() }
				}

				#[tracing::instrument(level = "debug", skip(self))]
				#vis async fn find(&self, id: &::uuid::Uuid) -> Result<#struct_name, crate::Error> {
					tracing::debug!(id=id.to_string(), sql=#find_query);
					let stmt = self.conn.prepare_cached(#find_query).await?;

					let res = self.conn.query(&stmt, &[&id]).await?;
					let row = res.get(0).ok_or(crate::Error::not_found(#table_name, "id", id.to_string()))?;

					#relation_loads

					#struct_name::from_row(row, #(#relation_values),*)
				}

				#[tracing::instrument(level = "debug", skip(self))]
				#vis fn find_by(&self) -> FindByBuilder<C> {
					FindByBuilder { conn: self.conn.clone(), inner: NewInner::default() }
				}

				#find_by_methods
			}

			#[automatically_derived]
			impl Handle<::deadpool_postgres::Client> {
				#vis async fn transaction(&mut self) -> Result<Handle<::deadpool_postgres::Transaction<'_>>, crate::Error> {
					Ok(Handle { conn: self.conn.transaction().await? })
				}
			}

			#[automatically_derived]
			impl Handle<::deadpool_postgres::Transaction<'_>> {
				#vis async fn commit(self) -> Result<(), crate::Error> {
					Ok(self.conn.commit().await?)
				}
			}

			impl<C: ::deadpool_postgres::GenericClient> ::std::ops::Deref for Handle<C> {
				type Target = C;

				fn deref(&self) -> &Self::Target {
					&self.conn
				}
			}

			#[derive(Debug)]
			#vis struct FindByBuilder<C: ::deadpool_postgres::GenericClient> {
				conn: crate::Conn<C>,
				inner: NewInner,
			}

			#[automatically_derived]
			impl<C: ::deadpool_postgres::GenericClient> FindByBuilder<C> {
				#(#find_by_builder_methods)*

				#vis async fn find(&self) -> Result<#struct_name, crate::Error> {
					todo!()
				}
			}
		});

		#[cfg(feature = "debug-macros")]
		if std::env::var("AUTHUL_DEBUG_MACROS").is_ok() {
			std::fs::write(
				&format!("/tmp/authul_table_macro_{struct_name}.rs"),
				tokens.to_string(),
			)
			.unwrap();
			let syntax_tree = syn::parse_file(&tokens.to_string()).unwrap();
			std::fs::write(
				&format!("/tmp/authul_table_macro_{struct_name}.rs"),
				prettyplease::unparse(&syntax_tree),
			)
			.unwrap();
		}

		tokens
	}
}

fn error<T>(span: &Span, desc: impl AsRef<str>) -> Result<T, TokenStream> {
	let e = desc.as_ref();

	Err(quote_spanned! { span.clone() => compile_error!(#e); })
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn errors() {
		let t = trybuild::TestCases::new();
		t.compile_fail("tests/errors/**/*.rs");
	}

	#[test]
	fn parse_empty_struct() {
		let s = Struct::from(
			syn::parse_file("struct Foo {}")
				.unwrap()
				.to_token_stream()
				.into(),
			Args::default(),
		)
		.unwrap();

		assert!(s.attrs.is_empty());
		assert!(s.vis.is_empty());
		assert_eq!("foos", s.table_name);
		assert_eq!("Foo", s.ident.to_string());
		assert!(s.fields.is_empty());
	}

	#[test]
	fn parse_visible_struct() {
		let s = Struct::from(
			syn::parse_file("pub(super) struct Foo {}")
				.unwrap()
				.to_token_stream()
				.into(),
			Args::default(),
		)
		.unwrap();

		assert!(s.attrs.is_empty());
		assert_eq!(
			"pub(super)",
			s.vis.into_iter().map(|v| v.to_string()).collect::<String>()
		);
		assert_eq!("foos", s.table_name);
		assert_eq!("Foo", s.ident.to_string());
		assert!(s.fields.is_empty());
	}

	#[test]
	fn parse_with_field() {
		let input = stringify! {
			struct Foo {
				bar: String,
			}
		};

		let s = Struct::from(
			syn::parse_file(input).unwrap().to_token_stream().into(),
			Args::default(),
		)
		.unwrap();

		assert!(s.attrs.is_empty());
		assert!(s.vis.is_empty());
		assert_eq!("foos", s.table_name);
		assert_eq!("Foo", s.ident.to_string());
		assert_eq!(1, s.fields.len());

		let f = &s.fields[0];

		assert_eq!("bar", f.ident.to_string());
		assert_eq!("String", f.ty.to_string());
		assert!(!f.belongs_to);
		assert!(!f.find_by);
		assert!(!f.find_all_by);
		assert!(f.default.is_empty());
	}

	#[test]
	fn parse_with_attributed_field() {
		let input = stringify! {
			struct Foo {
				#[column(find_all_by)]
				bar: String,
			}
		};

		let s = Struct::from(
			syn::parse_file(input).unwrap().to_token_stream().into(),
			Args::default(),
		)
		.unwrap();

		assert!(s.attrs.is_empty());
		assert!(s.vis.is_empty());
		assert_eq!("foos", s.table_name);
		assert_eq!("Foo", s.ident.to_string());
		assert_eq!(1, s.fields.len());

		let f = &s.fields[0];

		assert_eq!("bar", f.ident.to_string());
		assert_eq!("String", f.ty.to_string());
		assert!(!f.belongs_to);
		assert!(!f.find_by);
		assert!(f.find_all_by);
		assert!(f.default.is_empty());
	}
}
