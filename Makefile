all: build

build:
	@echo "binary build Starting."
	gcc -o fake-runc main.c
	@echo "binary build finished."

clean:
	rm -f fake-runc