DOC:=smartpgp_sm
REFS:=refs

default: $(DOC).pdf

$(DOC).dvi: $(DOC).tex $(REFS).bib
	latexmk -dvi -bibtex -f- -Werror $<

$(DOC).pdf: $(DOC).dvi
	dvipdfmx -q -D prepress -E -V 1.4 $<

.PHONY: clean
clean:
	latexmk -C $(DOC).tex

