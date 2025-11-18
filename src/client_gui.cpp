#include <stdio.h>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <vector>
#include <GLFW/glfw3.h>
#include "../libftpp/includes/network.hpp"

// Dear ImGui headers
#include <imgui.h>
#include <backends/imgui_impl_glfw.h>
#include <backends/imgui_impl_opengl3.h>

// Single Client instance used by the GUI
static Client gui_client;

// Simple helper to attempt connect using libftpp::Client
// Returns: 1 = username available and connected, 0 = username taken, -1 = error
static int attempt_connect(const std::string &host, int port, const std::string &username)
{
    std::cout << "Attempting connect to " << host << ':' << port << " as '" << username << "'\n";

    // If not connected yet, try to connect
    if (gui_client.getSocketFd() == -1) {
        gui_client.connect(host, port);
    }

    if (gui_client.getSocketFd() == -1) {
        std::cout << "Failed to connect to server." << std::endl;
        return -1;
    }

    // Ask server if username is available (this function currently sends a request and returns a stubbed value)
    int avail = gui_client.isUsernameAvailable(username);
    if (avail == 1) {
        std::cout << "Username '" << username << "' is available." << std::endl;
        return 1;
    } else if (avail == 0) {
        std::cout << "Username '" << username << "' is already taken." << std::endl;
        return 0;
    } else {
        std::cout << "Error checking username availability." << std::endl;
        return -1;
    }
}

int main(int, char**)
{
    // Setup GLFW
    if (!glfwInit())
        return 1;

    // GL 3.3 + GLSL 330
    const char* glsl_version = "#version 330";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    GLFWwindow* window = glfwCreateWindow(800, 600, "Client GUI", NULL, NULL);
    if (window == NULL)
        return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO(); (void)io;

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Style - customize to get a cleaner login card look
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 6.0f;
    style.FrameRounding = 6.0f;
    style.GrabRounding = 6.0f;

    // UI state
    static char username[128] = "";
    static char password[128] = "";
    static char host[128] = "127.0.0.1";
    static int port = 6668;
    std::string status_msg;

    enum AppState { STATE_LOGIN = 0, STATE_LOBBY = 1 } appState = STATE_LOGIN;
    std::vector<std::string> lobbyMessages;
    static char chatInput[512] = "";
    bool newMessageArrived = false;

    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();

        // Update network client to process incoming messages
        gui_client.update();

        // Start ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Fullscreen background window with no decoration
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        ImGui::SetNextWindowPos(ImVec2(0,0));
        ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize;

        ImGui::Begin("Background", NULL, flags);
        ImVec2 display = ImGui::GetWindowSize();

        // Centered login card
        const float card_w = 480.0f;
        const float card_h = 300.0f;
        ImVec2 card_pos = ImVec2((display.x - card_w) * 0.5f, (display.y - card_h) * 0.5f);
        ImGui::SetCursorPos(card_pos);

        // Card background (child) with nice padding
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.14f, 0.16f, 1.0f));
        ImGui::BeginChild("LoginCard", ImVec2(card_w, card_h), true, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        // Title and close
        ImGui::SetCursorPosX((card_w - 100.0f) * 0.5f);
        ImGui::Text("SERVER");
        ImGui::SameLine();
        ImGui::SetCursorPosX(card_w - 40.0f);
        if (ImGui::Button("X", ImVec2(28, 20))) {
            glfwSetWindowShouldClose(window, GLFW_TRUE);
        }

        ImGui::Dummy(ImVec2(0.0f, 10.0f));

        // Inputs (only show on login state)
        if (appState == STATE_LOGIN) {
            ImGui::PushItemWidth(card_w - 40.0f);
            ImGui::SetCursorPosX(20.0f);
            ImGui::Text("Host");
            ImGui::InputText("##host", host, IM_ARRAYSIZE(host));
            ImGui::SetCursorPosX(20.0f);
            ImGui::Text("Username");
            ImGui::InputText("##username", username, IM_ARRAYSIZE(username));
            // ImGui::SetCursorPosX(20.0f);
            // ImGui::Text("Password");
            // ImGui::InputText("##password", password, IM_ARRAYSIZE(password), ImGuiInputTextFlags_Password);

            ImGui::Spacing();
            ImGui::Spacing();
            ImGui::SetCursorPosX(20.0f);
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.176f, 0.549f, 0.941f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.216f, 0.627f, 0.996f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.137f, 0.471f, 0.863f, 1.0f));
            if (ImGui::Button("Log In", ImVec2(card_w - 40.0f, 44.0f)))
            {
                int status = attempt_connect(std::string(host), port, std::string(username));
                if (status == 1) {
                    status_msg = "Connected — username available.";
                    // Switch to lobby
                    appState = STATE_LOBBY;

                    // Register handler for incoming text messages
                    gui_client.defineAction(Message::Type::TEXT, [&](const Message& msg){
                        try {
                            Message m = msg; // copy so we can >>
                            std::string from;
                            std::string text;
                            m >> from >> text;
                            lobbyMessages.push_back(from + ": " + text);
                            newMessageArrived = true;
                        } catch (...) {
                            // ignore parse errors
                        }
                    });

                } else if (status == 0) {
                    status_msg = "Username already taken.";
                } else {
                    status_msg = "Connection or check failed.";
                }
            }
            ImGui::PopStyleColor(3);
            ImGui::PopItemWidth();
        }

        // If connected, show lobby UI instead of login inputs
        if (appState == STATE_LOBBY) {
            // Expand child to show lobby messages and input
            ImGui::BeginChild("LobbyArea", ImVec2(card_w - 40.0f, card_h - 110.0f), true);
            for (const auto& line : lobbyMessages) {
                ImGui::TextWrapped("%s", line.c_str());
            }
            if (newMessageArrived) {
                ImGui::SetScrollHereY(1.0f);
                newMessageArrived = false;
            }
            ImGui::EndChild();

            ImGui::Spacing();
            ImGui::SetCursorPosX(20.0f);
            ImGui::InputText("##chatinput", chatInput, IM_ARRAYSIZE(chatInput));
            ImGui::SameLine();
            if (ImGui::Button("Send", ImVec2(80, 24))) {
                std::string msgText(chatInput);
                if (!msgText.empty()) {
                    Message out(Message::Type::TEXT);
                    out << std::string(username) << msgText;
                    // Debug: print header bytes before sending to inspect endianness/size
                    {
                        const std::vector<uint8_t>& raw = out.rawData();
                        if (raw.size() >= 8) {
                            fprintf(stderr, "GUI: outgoing header bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7]);
                        }
                    }
                    gui_client.send(out);
                    lobbyMessages.push_back(std::string(username) + ": " + msgText);
                    chatInput[0] = '\0';
                    newMessageArrived = true;
                }
            }

            ImGui::SameLine();
            if (ImGui::Button("Disconnect", ImVec2(100,24))) {
                gui_client.disconnect();
                appState = STATE_LOGIN;
                status_msg = "Disconnected.";
                lobbyMessages.clear();
            }
        } else {
            // Status text
            if (!status_msg.empty()) {
                ImGui::Spacing();
                ImGui::SetCursorPosX(20.0f);
                ImGui::TextColored(ImVec4(1,0.6f,0.2f,1.0f), "%s", status_msg.c_str());
            }
        }

        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::End();

        // Rendering
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.08f, 0.12f, 0.16f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
