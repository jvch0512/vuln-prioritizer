# vuln-prioritizer: risk-based ordering of scanner findings. Base R only.

TIER_LABEL <- c(P0 = "fix now", P1 = "this sprint", P2 = "this quarter", P3 = "backlog")
CRIT_MULT  <- c(0.4, 0.6, 0.8, 1.0, 1.2)

as_flag <- function(x) tolower(trimws(as.character(x))) %in% c("true", "yes", "1", "y")

#' Reads a findings CSV: host, cve, cvss, epss, kev, criticality (1-5), exposed
read_findings <- function(path) {
  d <- read.csv(path, stringsAsFactors = FALSE, strip.white = TRUE)
  names(d) <- tolower(names(d))
  need <- c("host", "cve", "cvss")
  miss <- setdiff(need, names(d))
  if (length(miss)) stop("missing columns: ", paste(miss, collapse = ", "))
  d$cvss <- suppressWarnings(as.numeric(d$cvss))
  if (any(is.na(d$cvss) | d$cvss < 0 | d$cvss > 10)) stop("cvss must be a number between 0 and 10")
  d$epss <- if ("epss" %in% names(d)) suppressWarnings(as.numeric(d$epss)) else NA_real_
  d$epss[is.na(d$epss)] <- 0.01                       # unknown EPSS: the long-run median is about 1%
  d$epss <- pmin(pmax(d$epss, 0), 1)
  d$kev <- if ("kev" %in% names(d)) as_flag(d$kev) else FALSE
  crit <- if ("criticality" %in% names(d)) suppressWarnings(as.integer(d$criticality)) else rep(3L, nrow(d))
  crit[is.na(crit)] <- 3L
  d$criticality <- pmin(pmax(crit, 1L), 5L)
  d$exposed <- if ("exposed" %in% names(d)) as_flag(d$exposed) else FALSE
  d
}

#' Likelihood (0..1): exploitation probability, floored at 0.9 for known-exploited vulnerabilities.
likelihood <- function(epss, kev) ifelse(kev, pmax(epss, 0.9), epss)

#' Risk score 0..100 and tier.
prioritize <- function(d) {
  base <- d$cvss / 10
  l <- likelihood(d$epss, d$kev)
  exposure <- ifelse(d$exposed, 1.25, 1.0)
  d$score <- round(pmin(1, (0.35 * base + 0.65 * l) * CRIT_MULT[d$criticality] * exposure) * 100, 1)
  d$tier <- ifelse(d$kev & d$exposed, "P0",
            ifelse(d$score >= 70, "P0",
            ifelse(d$score >= 40, "P1",
            ifelse(d$score >= 20, "P2", "P3"))))
  d$cvss_only <- d$cvss >= 7
  d[order(-d$score, d$host, d$cve), ]
}

summarize <- function(d) {
  counts <- table(factor(d$tier, levels = names(TIER_LABEL)))
  list(
    total = nrow(d),
    tiers = counts,
    cvss_high = sum(d$cvss_only),
    p0p1 = sum(d$tier %in% c("P0", "P1")),
    hidden_gems = sum(!d$cvss_only & d$tier %in% c("P0", "P1")),       # low CVSS, high real risk
    noise = sum(d$cvss_only & d$tier %in% c("P2", "P3"))              # high CVSS, low real risk
  )
}

render_text <- function(d, top = 10) {
  s <- summarize(d)
  out <- c(sprintf("%d findings. CVSS 7+ alone would put %d in the urgent pile; risk-based ordering puts %d there (P0 and P1).",
                   s$total, s$cvss_high, s$p0p1),
           sprintf("%d high-CVSS findings drop to P2/P3 (low exploitation, low exposure). %d findings under CVSS 7 rise to P0/P1.", s$noise, s$hidden_gems),
           "", sprintf("%-4s %-5s %-15s %-14s %5s %5s %-3s %s", "tier", "score", "host", "cve", "cvss", "epss", "kev", "why"))
  for (i in seq_len(min(top, nrow(d)))) {
    r <- d[i, ]
    why <- c(if (r$kev) "known exploited", if (r$exposed) "internet-facing", if (r$epss >= 0.5) "likely exploited soon", if (r$criticality >= 4) "critical asset")
    out <- c(out, sprintf("%-4s %5.1f %-15s %-14s %5.1f %5.2f %-3s %s", r$tier, r$score, r$host, r$cve, r$cvss, r$epss, if (r$kev) "yes" else "no", paste(why, collapse = ", ")))
  }
  paste0(paste(out, collapse = "\n"), "\n")
}

esc <- function(x) { x <- gsub("&", "&amp;", x, fixed = TRUE); x <- gsub("<", "&lt;", x, fixed = TRUE); x <- gsub(">", "&gt;", x, fixed = TRUE); gsub("\"", "&quot;", x, fixed = TRUE) }

render_html <- function(d, top = 15) {
  s <- summarize(d)
  colors <- c(P0 = "#f85149", P1 = "#f0883e", P2 = "#e3b341", P3 = "#3fb950")
  mx <- max(1, s$tiers)
  bars <- paste(vapply(seq_along(s$tiers), function(i) {
    t <- names(s$tiers)[i]; w <- round(300 * s$tiers[[i]] / mx)
    sprintf("<div class=\"row\"><span class=\"lab\">%s %s</span><svg width=\"320\" height=\"18\" role=\"img\" aria-label=\"%s: %d\"><rect x=\"0\" y=\"2\" width=\"%d\" height=\"14\" rx=\"3\" fill=\"%s\"/></svg><span>%d</span></div>",
            t, esc(TIER_LABEL[[t]]), t, s$tiers[[i]], max(w, 2), colors[[t]], s$tiers[[i]])
  }, character(1)), collapse = "")
  rows <- paste(vapply(seq_len(min(top, nrow(d))), function(i) {
    r <- d[i, ]
    sprintf("<tr><td class=\"%s\">%s</td><td>%.1f</td><td>%s</td><td>%s</td><td>%.1f</td><td>%.2f</td><td>%s</td><td>%s</td></tr>",
            r$tier, r$tier, r$score, esc(r$host), esc(r$cve), r$cvss, r$epss, if (r$kev) "yes" else "", if (r$exposed) "yes" else "")
  }, character(1)), collapse = "")
  paste0("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>vuln-prioritizer</title><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}h2{margin:24px 0 8px;font-size:16px}.sub{color:#8b98a8}.row{display:flex;align-items:center;gap:10px}.lab{width:150px}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #2a3441}th{color:#8b98a8}.P0{color:#f85149;font-weight:700}.P1{color:#f0883e;font-weight:700}.P2{color:#e3b341;font-weight:700}.P3{color:#3fb950;font-weight:700}</style></head><body><h1>vuln-prioritizer</h1><p class=\"sub\">Risk-based vulnerability prioritization in R, base R only. Synthetic findings with fictional CVE-2099 identifiers.</p>",
         sprintf("<p>%d findings. CVSS 7+ alone would call <b>%d</b> urgent. Risk-based ordering calls <b>%d</b> urgent, drops <b>%d</b> high-CVSS findings to P2/P3, and raises <b>%d</b> findings under CVSS 7 to P0/P1.</p>", s$total, s$cvss_high, s$p0p1, s$noise, s$hidden_gems),
         "<h2>Findings per tier</h2>", bars, "<h2>Top of the queue</h2><table><tr><th>Tier</th><th>Score</th><th>Host</th><th>CVE</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Exposed</th></tr>", rows,
         "</table><p class=\"sub\">Score = (0.35 x CVSS + 0.65 x exploitation likelihood) x asset criticality x exposure. Known-exploited and internet-facing is always P0. EPSS and KEV values come from your own export, nothing is fetched.</p></body></html>\n")
}
