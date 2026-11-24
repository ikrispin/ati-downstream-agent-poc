# Native LSCore visual guide sources

The Word guide and all six diagrams describe the native LSCore PoC.
SVG files are the editable diagram sources. PNG files are their high-resolution
document images; they contain no live source reports or credentials.

`build_visual_guide.py` generates both diagrams and the Word document. It expects
the configured document-authoring runtime: Python with `python-docx`, and Node
with `sharp`, in a dependency directory containing `python/bin`, `node/bin`, and
`node/node_modules`. Pass that directory explicitly:

```bash
<BUNDLED_PYTHON> build_visual_guide.py --runtime-root <BUNDLED_DEPENDENCIES>
```

The PoC runtime does not depend on those authoring packages. After changing the
guide, render the DOCX with the document renderer and inspect every page for
clipping, overlapping arrows and stale architecture labels. Keep rendered QA
pages and PDFs under ignored `.local`; publish the final DOCX and diagram sources.
