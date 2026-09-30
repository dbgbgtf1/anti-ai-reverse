all: runner

runner:
	python scripts\extract.py src\puzzle.c
	python scripts\extract.py src\hack.c --no-seed
	python scripts\auto_regressive.py build\payload.bin
	clang -g src\runner.c src\generate.c -o runner.exe
