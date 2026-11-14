test:
	Rscript tests/test.R

sample:
	Rscript bin/vuln-prioritizer examples/findings.csv > docs/sample-output.txt
	Rscript bin/vuln-prioritizer examples/findings.csv --html > site/index.html
