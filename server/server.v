// server binds the S3 service to a listening socket. It is deliberately thin:
// the service already decides what a request means, and the HTTP stack already
// parses bytes into a request. This layer only connects the two and reports
// liveness, so a probe can tell a running process from a started one.
module server

import os
import net.http
import admin
import iceberg
import s3
import swift
import webdav

// Endpoint serves S3 on one address, plus the admin API when one is configured.
pub struct Endpoint {
pub mut:
	service  s3.Service
	admin        ?admin.Service
	dav_only     bool
	swift_tokens &swift.Tokens = unsafe { nil }
}

pub fn (mut e Endpoint) handle(req http.Request) http.Response {
	if req.url.starts_with('/iceberg/v1') || req.url.starts_with('/_iceberg/v1') {
		root := if e.service.volume.drives.len == 0 {
			os.temp_dir()
		} else {
			os.join_path(e.service.volume.drives[0].root(), 'iceberg')
		}
		return iceberg.handle(req, root)
	}
	if req.url.starts_with('/health') {
		return e.health(req)
	}
	if !e.dav_only && (req.url.starts_with('/auth/v1.0') || req.url.starts_with('/v1/')) {
		return e.swift().handle(req)
	}
	if e.dav_only || webdav.wants(req) {
		return e.dav().handle(req)
	}
	if mut configured := e.admin {
		if response := configured.handle(req) {
			return response
		}
	}
	return e.service.handle(req)
}

fn (e Endpoint) health(req http.Request) http.Response {
	path := req.url.all_before('?')
	if path == '/health/ready' || path.starts_with('/health/ready/') {
		if !e.service.volume.ready() {
			return http.new_response(
				status: .service_unavailable
				body:   'not ready'
			)
		}
	}
	return http.new_response(
		status: .ok
		body:   'ok'
	)
}

fn (e Endpoint) swift() swift.Service {
	return swift.Service{
		volume:    e.service.volume
		creds:     e.service.creds
		directory: e.service.directory
		tokens:    e.swift_tokens
	}
}

fn (e Endpoint) dav() webdav.Service {
	return webdav.Service{
		volume:    e.service.volume
		creds:     e.service.creds
		directory: e.service.directory
	}
}

// serve_async runs a listener on another thread. The endpoint is copied so the
// caller's value stays with the API listener.
pub fn serve_async(e &Endpoint, addr string) {
	mut local := *e
	serve(mut local, addr) or {
		eprintln('vfs: listener ${addr}: ${err}')
	}
}

// serve listens until the process is stopped. It does not return on success.
pub fn serve(mut e Endpoint, addr string) ! {
	mut http_server := http.Server{
		addr:                 addr
		handler:              e
		show_startup_message: false
	}
	println('vfs listening on http://${addr}/')
	http_server.listen_and_serve()
	if http_server.addr == '' {
		return error('listener failed to start on ${addr}')
	}
}
