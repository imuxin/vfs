FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY vfs /usr/local/bin/vfs
EXPOSE 9000
ENV VFS_ACCESS_KEY=vfsadmin \
    VFS_SECRET_KEY=vfsadmin \
    VFS_REGION=us-east-1
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/vfs"]
CMD ["server", "/data", ":9000"]
