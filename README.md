# Sing-box Config Converter Web UI

A simple, client-side web application to convert various proxy subscription links (VMESS, VLESS, Trojan, Shadowsocks, ShadowsocksR, Socks, HTTP/S) into a unified Sing-box JSON configuration, based on a customizable base template.

The application runs entirely in your browser using HTML, CSS, and JavaScript, requiring no server-side processing.

## ✨ Features

*   **Multi-Protocol Support:** Convert VMESS, VLESS, Trojan, Shadowsocks (SS), ShadowsocksR (SSR), Socks (Socks5), and HTTP/S proxy URLs.
*   **Template Selection:** Choose between different predefined Sing-box base templates to structure your final configuration (e.g., a v1.12-like complex template and a v1.11-like simple template).
*   **Config Customization:** A detailed settings page allows you to easily modify common parameters within the chosen template, including:
    *   Log Level and Timestamp
    *   Inbound Listen Addresses and Ports (Mixed, TUN HTTP Proxy)
    *   TUN settings (NAT, Auto Route, MTU)
    *   DNS Servers (Remote/Proxy, Direct) and Cache settings
    *   Routing settings (Final Outbound, Default Resolver, Auto Detect Interface)
    *   Remote Rule Set settings (Enable/Disable, Download Detour, Update Interval)
    *   Experimental/Clash API settings (Controller, UI URL, UI Download Detour, Cache File options)
*   **Automatic Tagging:** Parsed proxies are assigned unique tags to avoid conflicts.
*   **Selector Integration:** Converted proxies are automatically added to specific selector/urltest outbounds within the template (by default, outbounds tagged "proxy" and "Auto", if they exist and are of type `selector` or `urltest`).
*   **Intelligent DNS Adjustment:** Basic logic to modify DNS rules if no domain-based outbound servers are successfully parsed (e.g., potentially removing rules that rely on remote DNS servers if they are unreachable via domain proxies).
*   **Clean Output:** Automatically removes `null` and `undefined` values from the generated JSON config.
*   **Copy & Download:** Easily copy the generated config to your clipboard or download it as a `.json` file.
*   **Responsive UI:** Designed to be usable on both desktop and mobile screens.
*   **Client-Side:** All processing happens in your browser. Your proxy details and configurations are not sent to any server.

## 🚀 How to Use

1.  **Download the Files:** Save the following three files into the *same folder*:
    *   `index.html`
    *   `style.css`
    *   `script.js`
2.  **Open in Browser:** Double-click `index.html` or open it with your preferred web browser.
3.  **Input Proxy URLs:**
    *   Select your desired base template from the "Choose Base Template" dropdown.
    *   Paste your proxy URLs (one per line) into the "Input Proxy URLs" textarea.
    *   Click the "Next: Configure Template" button.
4.  **Customize Template Settings:**
    *   Fill out or adjust the parameters in the form fields. The fields will show the default values from the template you selected in the previous step.
    *   Click the "Reset Settings" button to revert all fields to the defaults of the *currently selected* template.
    *   Click the "Generate Config" button when you are ready.
5.  **Generated Sing-box Configuration:**
    *   The final Sing-box JSON configuration will appear in the textarea.
    *   Review the config.
    *   Use the "Copy Config" button to copy the JSON to your clipboard.
    *   Use the "Download Config" button to save the JSON as a file (`.json`).
    *   Click "Back to Settings" if you need to make changes to the template parameters and regenerate.

## 📂 Project Structure

your-project-folder/
├── index.html    - The main HTML file for the user interface.
├── style.css     - Contains all the CSS for styling the UI.
└── script.js     - Contains all the JavaScript logic for parsing, template modification, UI interaction, and output.


## 🛠️ Customization & Development

*   **Base Templates:** The core Sing-box templates are embedded directly within `script.js` (`templateV1_12`, `templateV1_11`). If you need to add a new template or fundamentally change the existing ones beyond the parameters exposed in the UI, you will need to edit `script.js` directly. Ensure any new template includes an `outbounds` array and preferably outbounds tagged "proxy" and "Auto" (of type selector or urltest) for automatic proxy insertion.
*   **Exposed Parameters:** The script exposes a specific set of parameters in the settings form based on the provided templates. If your custom template has different parameters you want to expose via the UI, you would need to modify both the `index.html` (to add the form fields) and the `script.js` (`populateSettingsForm` and `applySettingsToTemplate` functions) to handle them.
*   **Parsing Logic:** The parsing logic for each protocol is also in `script.js` within the `v2rayToSing` function. If you encounter URLs that aren't parsed correctly or need to support new protocols, this is where you would make modifications.
*   **Build Tools:** The project uses pure client-side HTML, CSS, and JS. No build tools (like Webpack, Babel) are required.

## 📜 License

This project is provided under the [MIT License](https://opensource.org/licenses/MIT). You are free to use, modify, and distribute the code, provided the original license is included.

MIT License

Copyright (c) 2025 SBC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
