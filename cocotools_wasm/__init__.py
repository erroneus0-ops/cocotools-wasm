"""
cocotools_wasm -- WASM-backed CoCo development tools

A Python interface to WebAssembly builds of lwasm and toolshed.
This is the production implementation. For the reference Python
translation see cocotools/.

Architecture:
    WASM layer:   wasm/lwasm/lwasm.wasm  (William Astle's lwasm, compiled)
                  wasm/toolshed/*.wasm   (toolshed utilities, compiled)
    Python layer: cocotools_wasm/        (this package -- friendly wrapper)
    CLI:          cocotools_wasm/cli.py  (same interface as cocotools.py)

Why WASM over Python translation:
    The Python translation in cocotools/ is a simulation of lwasm within
    a language not specifically geared to match C semantics. The WASM
    build is William's actual assembler running in a sandbox. Faithfulness
    is inherent, not achieved through careful translation and testing.
"""
