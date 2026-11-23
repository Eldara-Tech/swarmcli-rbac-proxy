# Troubleshooting

Symptoms you are likely to see in the proxy's output, and what they actually mean.

For the RBAC model see [rbac.md](rbac.md), for the configuration surface see
[configuration.md](configuration.md), and for the threat model see
[security.md](security.md).

## `http: proxy error: context canceled`

**This is about the caller, not the proxy.** It does not indicate a proxy fault or
a Docker daemon problem.

Two things narrow it down:

- Only a failed **`RoundTrip`** reaches this handler. A failure while copying the
  response body panics with `http.ErrAbortHandler` instead. So the message means
  the request never got response headers back at all.
- `context canceled` on the inbound request means **the client connection
  closed**. `http.Server` cancels the request context with `context.Canceled`
  whatever the client's own reason was — a deadline on the caller's side arrives
  here as "canceled", not "deadline exceeded". The message therefore says nothing
  about *why* the caller went away.

**N identical lines sharing one timestamp is the real signal.** That is one client
cancelling N in-flight requests at the same instant — the shape of a fan-out
sharing a single cancelled context, not N independent failures. Look at what the
caller was doing, not at the proxy.

### Why it used to look like a proxy fault

The line was printed by stdlib `log` rather than zap, which is the giveaway: it
came from `httputil.ReverseProxy`'s **default** error handler, because `ErrorLog`
was unset. Everything else the proxy writes is structured, so this one line
arrived in a different format and read as something escaping the logger.

Fixed in #152, which sets both `ErrorLog` and `ErrorHandler` and demotes this
case to debug. If you see it at info level, the build predates that fix.
