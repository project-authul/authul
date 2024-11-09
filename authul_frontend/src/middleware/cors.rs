use actix_web::{
	dev::{Service, ServiceRequest, ServiceResponse, Transform},
	http::{
		header::{HeaderName, HeaderValue},
		Method, StatusCode,
	},
	Error as ActixError,
};
use pin_project::pin_project;
use std::{
	future::{ready, Future, Ready},
	marker::PhantomData,
	pin::Pin,
	task::{ready, Context, Poll},
};

const HEADER_ACAO: HeaderName = HeaderName::from_static("access-control-allow-origin");
const VALUE_WILDCARD: HeaderValue = HeaderValue::from_static("*");
const HEADER_ACAM: HeaderName = HeaderName::from_static("access-control-allow-methods");
const VALUE_GET_METHODS: HeaderValue = HeaderValue::from_static("GET, HEAD, OPTIONS");
const VALUE_POST_METHODS: HeaderValue = HeaderValue::from_static("POST, OPTIONS");
const HEADER_ACMA: HeaderName = HeaderName::from_static("access-control-max-age");
const VALUE_ONE_WEEK: HeaderValue = HeaderValue::from_static("604800");

pub(crate) enum Cors {
	GET,
	POST,
}

impl<S, B> Transform<S, ServiceRequest> for Cors
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
	S::Future: 'static,
{
	type Response = ServiceResponse<B>;
	type Error = ActixError;
	type Transform = CorsMiddleware<S>;
	type InitError = ();
	type Future = Ready<Result<Self::Transform, Self::InitError>>;

	fn new_transform(&self, service: S) -> Self::Future {
		let methods = match self {
			Cors::GET => VALUE_GET_METHODS,
			Cors::POST => VALUE_POST_METHODS,
		};
		ready(Ok(CorsMiddleware { service, methods }))
	}
}

pub(crate) struct CorsMiddleware<S> {
	service: S,
	methods: HeaderValue,
}

impl<S, B> Service<ServiceRequest> for CorsMiddleware<S>
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
	S::Future: 'static,
{
	type Response = S::Response;
	type Error = S::Error;
	type Future = CorsFuture<S, B>;

	actix_web::dev::forward_ready!(service);

	fn call(&self, req: ServiceRequest) -> Self::Future {
		CorsFuture {
			options_request: req.method() == Method::OPTIONS,
			methods: self.methods.clone(),
			call_future: self.service.call(req),
			_body: PhantomData,
		}
	}
}

#[pin_project]
pub(crate) struct CorsFuture<S: Service<ServiceRequest>, B> {
	#[pin]
	call_future: S::Future,
	methods: HeaderValue,
	options_request: bool,
	_body: PhantomData<B>,
}

impl<S, B> Future for CorsFuture<S, B>
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
{
	type Output = <S::Future as Future>::Output;

	fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = self.as_mut().project();
		let mut res = ready!(this.call_future.poll(ctx))?;

		if res.status().as_u16() == 405 && self.options_request {
			*res.response_mut().status_mut() = StatusCode::NO_CONTENT;
		}

		res.headers_mut().insert(HEADER_ACAO, VALUE_WILDCARD);
		res.headers_mut().insert(HEADER_ACAM, self.methods.clone());
		res.headers_mut().insert(HEADER_ACMA, VALUE_ONE_WEEK);

		Poll::Ready(Ok(res))
	}
}
