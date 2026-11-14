source("R/prioritize.R")
n <- 0; failed <- 0
check <- function(name, ok) { n <<- n + 1; if (!isTRUE(ok)) { failed <<- failed + 1; cat("FAIL:", name, "\n") } }
mk <- function(cvss = 5, epss = 0.01, kev = "no", crit = 3, exposed = "no", host = "h", cve = "CVE-2099-0001")
  data.frame(host = host, cve = cve, cvss = cvss, epss = epss, kev = kev, criticality = crit, exposed = exposed, stringsAsFactors = FALSE)
tmp <- function(df) { p <- tempfile(fileext = ".csv"); write.csv(df, p, row.names = FALSE); p }
tier <- function(...) prioritize(read_findings(tmp(mk(...))))$tier

check("as_flag understands yes/true/1", all(as_flag(c("yes", "TRUE", "1", " y "))) && !any(as_flag(c("no", "false", "0", ""))))
check("kev floors likelihood at 0.9", likelihood(0.1, TRUE) == 0.9 && likelihood(0.95, TRUE) == 0.95 && likelihood(0.1, FALSE) == 0.1)
check("known exploited and exposed is always P0", tier(cvss = 3, kev = "yes", exposed = "yes", crit = 1) == "P0")
check("critical CVSS, tiny EPSS, internal low-value asset is not urgent", tier(cvss = 9.8, epss = 0.01, crit = 1) == "P3")
check("same finding on a critical internet-facing asset ranks higher",
      prioritize(read_findings(tmp(rbind(mk(cvss = 9.8, epss = 0.3, crit = 1, host = "a"), mk(cvss = 9.8, epss = 0.3, crit = 5, exposed = "yes", host = "b")))))$host[1] == "b")
check("medium CVSS with high EPSS on an exposed critical asset is urgent", tier(cvss = 6.5, epss = 0.7, crit = 5, exposed = "yes") == "P0")
check("score is capped at 100 and floored above 0", {
  d <- prioritize(read_findings(tmp(rbind(mk(cvss = 10, epss = 1, kev = "yes", crit = 5, exposed = "yes"), mk(cvss = 0.1, epss = 0, crit = 1)))))
  max(d$score) == 100 && min(d$score) >= 0 })
check("results are sorted by score, ties by host", {
  d <- prioritize(read_findings(tmp(rbind(mk(host = "z", cvss = 9, epss = 0.5), mk(host = "a", cvss = 2, epss = 0.0)))))
  d$host[1] == "z" && !is.unsorted(rev(d$score)) })
check("unknown EPSS defaults to 1%", read_findings(tmp(mk(epss = NA)))$epss == 0.01)
check("EPSS is clamped to 0..1", all(read_findings(tmp(rbind(mk(epss = 7), mk(epss = -1))))$epss %in% c(0, 1)))
check("optional columns may be missing", {
  p <- tempfile(fileext = ".csv"); writeLines(c("host,cve,cvss", "h,CVE-2099-1,7.5"), p)
  d <- read_findings(p); d$criticality == 3 && !d$kev && !d$exposed })
check("missing required column is an error", inherits(try(read_findings({ p <- tempfile(); writeLines(c("host,cve", "h,c"), p); p }), silent = TRUE), "try-error"))
check("cvss out of range is an error", inherits(try(read_findings(tmp(mk(cvss = 11))), silent = TRUE), "try-error"))
check("criticality is clamped to 1..5", all(read_findings(tmp(rbind(mk(crit = 9), mk(crit = 0))))$criticality %in% c(1L, 5L)))
check("summary counts", { s <- summarize(prioritize(read_findings(tmp(rbind(mk(cvss = 9.8, crit = 1), mk(cvss = 5, epss = 0.9, kev = "yes", exposed = "yes")))))); s$total == 2 && s$cvss_high == 1 && s$noise == 1 && s$hidden_gems == 1 })
check("html escapes hostnames and CVE ids", {
  h <- render_html(prioritize(read_findings(tmp(mk(host = "<script>alert(1)</script>", cve = "<b>x</b>")))))
  !grepl("<script>alert", h, fixed = TRUE) && grepl("&lt;script&gt;", h, fixed = TRUE) && grepl("default-src 'none'", h, fixed = TRUE) })
check("text report mentions the headline", grepl("CVSS 7+ alone", render_text(prioritize(read_findings(tmp(mk())))), fixed = TRUE))

if (file.exists("examples/findings.csv")) {
  d <- prioritize(read_findings("examples/findings.csv")); s <- summarize(d)
  check("sample: 39 findings", s$total == 39)
  check("sample: 23 findings have CVSS 7+", s$cvss_high == 23)
  check("sample: a handful are really urgent", s$p0p1 >= 4 && s$p0p1 <= 8)
  check("sample: most high-CVSS findings drop to P2/P3", s$noise >= 15)
  check("sample: a sub-7 CVSS finding is raised to P0/P1", s$hidden_gems >= 1)
  check("sample: the known-exploited internet-facing VPN gateway is first tier", d$tier[d$host == "vpn-gw"][1] == "P0")
} else cat("skipped sample tests (run from repo root)\n")
cat(if (failed == 0) sprintf("all %d passed\n", n) else sprintf("%d of %d failed\n", failed, n))
quit(status = if (failed == 0) 0 else 1)
