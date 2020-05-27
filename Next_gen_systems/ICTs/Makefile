
# We need to recompile several times so that we can
# fix forward references

TRASH = *.aux *.log *.toc

all: designing_an_ict

designing_an_ict: Designing_an_ICT.tex
	pdflatex Designing_an_ICT.tex
	pdflatex Designing_an_ICT.tex
	rm -f $(TRASH)

.PHONY: clean

clean:
	rm -f $(TRASH) *.pdf
