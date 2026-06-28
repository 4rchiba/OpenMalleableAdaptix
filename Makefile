.PHONY: all clean

all:
	@echo "Building open_malleable_listener..."
	@$(MAKE) -C open_malleable_listener
	@echo "Building open_malleable_agent..."
	@$(MAKE) -C open_malleable_agent

clean:
	@$(MAKE) -C open_malleable_listener clean
	@$(MAKE) -C open_malleable_agent clean
