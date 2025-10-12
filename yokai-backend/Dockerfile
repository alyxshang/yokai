FROM --platform=linux/amd64 archlinux:base-devel AS builder
WORKDIR /yokai-backend
RUN pacman-db-upgrade
RUN pacman -Syyu --noconfirm
RUN pacman -S base-devel rust postgresql --noconfirm
RUN cargo install sqlx-cli --no-default-features --features postgres 
COPY . .
ENV SQLX_OFFLINE=true
RUN cargo clean
RUN cargo build --release

FROM --platform=linux/amd64 archlinux:base-devel
COPY --from=builder /yokai-backend/target/release/yokai-backend /yokai-backend
ENTRYPOINT ["/yokai-backend"]
EXPOSE 3000
