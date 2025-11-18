# Simple Makefile to build the test GLFW/OpenGL binary
# Usage:
# make          # builds the 'test' target
# make test
# make run      # runs the built binary
# make clean

CXX := g++
SRC := src/test.cpp
BUILD_DIR := build
TARGET := $(BUILD_DIR)/test

# Try to get flags from pkg-config, fall back to common locations if not available
PKG_CFLAGS := $(shell pkg-config --cflags glfw3 2>/dev/null)
PKG_LIBS := $(shell pkg-config --libs glfw3 2>/dev/null)

CXXFLAGS := -std=c++11 $(PKG_CFLAGS)
LDFLAGS := $(PKG_LIBS) -lGL -lm -ldl -lpthread -lX11 -lXrandr -lXi -lssl -lcrypto


.PHONY: all test launch_serv run-launch run clean

all: test launch_serv

test: $(TARGET)

$(TARGET): $(SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $< $(LDFLAGS) -o $@

run: $(TARGET)
	@echo "Running $(TARGET)"
	$(TARGET)

clean:
	-rm -rf $(BUILD_DIR)

# -----------------------
# launch_serv (uses libftpp)
# -----------------------
LIBFTPP_DIR := libftpp
LIBFTPP_SRCS := $(wildcard $(LIBFTPP_DIR)/srcs/*.cpp)
LIBFTPP_OBJS := $(patsubst $(LIBFTPP_DIR)/srcs/%.cpp,$(BUILD_DIR)/libftpp/%.o,$(LIBFTPP_SRCS))

TARGET_LAUNCH := $(BUILD_DIR)/launch_serv

launch_serv: $(TARGET_LAUNCH)

$(BUILD_DIR)/libftpp/%.o: $(LIBFTPP_DIR)/srcs/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -I$(LIBFTPP_DIR)/includes -c $< -o $@

$(TARGET_LAUNCH): src/launch_serv.cpp $(LIBFTPP_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $< $(LIBFTPP_OBJS) $(LDFLAGS) -o $@

run-launch: $(TARGET_LAUNCH)
	@echo "Running $(TARGET_LAUNCH)"
	$(TARGET_LAUNCH)

# -----------------------
# client GUI (ImGui + GLFW)
# -----------------------
IMGUICFLAGS := $(shell pkg-config --cflags imgui 2>/dev/null)
IMGUILIBS := $(shell pkg-config --libs imgui 2>/dev/null)

CLIENT_GUI_SRC := src/client_gui.cpp
CLIENT_GUI_TARGET := $(BUILD_DIR)/client_gui


# ImGui fetch/build settings
IMGUI_DIR := third_party/imgui
IMGUI_REPO := https://github.com/ocornut/imgui.git
IMGUI_SRCS := $(IMGUI_DIR)/imgui.cpp $(IMGUI_DIR)/imgui_draw.cpp $(IMGUI_DIR)/imgui_widgets.cpp $(IMGUI_DIR)/imgui_tables.cpp $(IMGUI_DIR)/imgui_demo.cpp
IMGUI_BACKENDS := $(IMGUI_DIR)/backends/imgui_impl_glfw.cpp $(IMGUI_DIR)/backends/imgui_impl_opengl3.cpp

client_gui: $(CLIENT_GUI_TARGET)

$(IMGUI_DIR):
	@echo "Cloning Dear ImGui into $(IMGUI_DIR) (this requires network access)"
	@git clone --depth 1 $(IMGUI_REPO) $(IMGUI_DIR)

$(CLIENT_GUI_TARGET): $(CLIENT_GUI_SRC) $(LIBFTPP_OBJS) | $(IMGUI_DIR)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(IMGUICFLAGS) $< $(IMGUI_SRCS) $(IMGUI_BACKENDS) $(LIBFTPP_OBJS) $(LDFLAGS) $(IMGUILIBS) -I$(IMGUI_DIR) -I$(IMGUI_DIR)/backends -I$(LIBFTPP_DIR)/includes -o $@

run-client: $(CLIENT_GUI_TARGET)
	@echo "Running $(CLIENT_GUI_TARGET)"
	$(CLIENT_GUI_TARGET)



