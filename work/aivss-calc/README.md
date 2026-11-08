# OWASP AIVSS 1.0 reference calculator (source)

This directory is the source for the OWASP AIVSS 1.0 reference calculator published at https://aivss.owasp.org/calculator/.

## Run tests

`ash
pip install -e .
PYTHONPATH=. python3 -m pytest -q
`

## Rebuild the published site

From this directory:

`ash
PYTHONPATH=. python3 scripts/build_static_site.py _site /calculator/
rm -rf _site/assets _site/slides.html
`

Then replace ../calculator with the contents of _site.
