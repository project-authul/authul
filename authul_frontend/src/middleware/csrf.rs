use actix_web::{
	cookie::{Cookie, SameSite},
	dev::{Service, ServiceRequest, ServiceResponse, Transform},
	Error as ActixError,
};
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use pin_project::pin_project;
use rand::{thread_rng, Rng};
use std::{
	future::{ready, Future, Ready},
	marker::PhantomData,
	pin::Pin,
	task::{ready, Context, Poll},
};

pub(crate) struct Csrf {
	domain: String,
	path: String,
}

impl Csrf {
	pub(crate) fn new(domain: impl Into<String>, path: impl Into<String>) -> Self {
		Self {
			domain: domain.into(),
			path: path.into(),
		}
	}
}

impl<S, B> Transform<S, ServiceRequest> for Csrf
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
	S::Future: 'static,
{
	type Response = ServiceResponse<B>;
	type Error = ActixError;
	type Transform = CsrfMiddleware<S>;
	type InitError = ();
	type Future = Ready<Result<Self::Transform, Self::InitError>>;

	fn new_transform(&self, service: S) -> Self::Future {
		ready(Ok(CsrfMiddleware {
			service,
			domain: self.domain.clone(),
			path: self.path.clone(),
		}))
	}
}

pub(crate) struct CsrfMiddleware<S> {
	service: S,
	domain: String,
	path: String,
}

impl<S, B> Service<ServiceRequest> for CsrfMiddleware<S>
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
	S::Future: 'static,
{
	type Response = S::Response;
	type Error = S::Error;
	type Future = CsrfFuture<S, B>;

	actix_web::dev::forward_ready!(service);

	fn call(&self, req: ServiceRequest) -> Self::Future {
		CsrfFuture {
			has_csrf_token: req.cookie("csrf_token").is_some(),
			domain: self.domain.clone(),
			path: self.path.clone(),
			call_future: self.service.call(req),
			_body: PhantomData,
		}
	}
}

#[pin_project]
pub(crate) struct CsrfFuture<S: Service<ServiceRequest>, B> {
	#[pin]
	call_future: S::Future,
	has_csrf_token: bool,
	domain: String,
	path: String,
	_body: PhantomData<B>,
}

impl<S: Service<ServiceRequest>, B> CsrfFuture<S, B> {
	fn cookie(&self) -> Cookie {
		cookie(&self.domain, &self.path)
	}
}

impl<S, B> Future for CsrfFuture<S, B>
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
{
	type Output = <S::Future as Future>::Output;

	fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = self.as_mut().project();
		let mut res = ready!(this.call_future.poll(ctx))?;

		if !self.has_csrf_token {
			(*res.response_mut())
				.add_cookie(&self.cookie())
				.expect("add_cookie failed somehow");
		}

		Poll::Ready(Ok(res))
	}
}

pub(crate) fn cookie(domain: impl Into<String>, path: impl Into<String>) -> Cookie<'static> {
	Cookie::build("csrf_token", random_string())
		.domain(domain.into())
		.path(path.into())
		.http_only(true)
		.secure(true)
		.same_site(SameSite::Lax)
		.finish()
}

fn random_string() -> String {
	let chonk: Vec<u8> = (0..16).map(|_| thread_rng().gen::<u8>()).collect();
	BASE64_URL_SAFE_NO_PAD.encode(&chonk)
}
