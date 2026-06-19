FROM gcc:13-alpine
WORKDIR /app
COPY . .
RUN gcc -o app src/main.c
CMD ["./app"]
