FROM rust:alpine as rust-build

RUN rustup target add x86_64-unknown-linux-musl \
	&& rustup target add wasm32-unknown-unknown \
	&& apk add build-base \
	&& cargo install --locked cargo-leptos --git https://github.com/mpalmer/cargo-leptos-fork.git --branch bin-target-env \
	&& mkdir /build

# Fuck you, Docker.  Fuck you *HARD*.
COPY Cargo.* /build
COPY authul_crypto /build/authul_crypto
COPY authul_db /build/authul_db
COPY authul_frontend /build/authul_frontend
COPY authul_macros /build/authul_macros
COPY authul_oauth2 /build/authul_oauth2
COPY authul_util /build/authul_util
COPY authul_xtask /build/authul_xtask
COPY src /build/src
COPY tests /build/tests

WORKDIR /build

RUN --mount=type=cache,target=/build/target,id=authul-rust-build-target \
	--mount=type=cache,target=/usr/local/cargo/registry,id=authul-rust-build-registry \
	LEPTOS_BIN_EXE_NAME=authul LEPTOS_BIN_FEATURES=frontend-ssr,cli LEPTOS_BIN_TARGET=authul cargo leptos build --release \
	&& cp target/release/authul /build/authul

FROM scratch

COPY --from=rust-build /build/authul /authul

ENV PATH /
ENTRYPOINT ["/authul"]
