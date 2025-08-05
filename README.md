# TOTP
TOTP is an extension for Burp Suite that allows you to generate and use time-based one-time passwords. TOTP codes are generated according to the standard outlined in [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238). The extension supports both Burp Suite's Professional and Community editions.

![Screenshot of the extension's tab in Burp Suite.](/images/TOTP%20Tab.png)

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Adding a code](#adding-a-code)
  - [Scanning QR Codes](#scanning-qr-codes)
  - [Setting your Scope](#setting-your-scope)
  - [Session handling rules](#session-handling-rules)
  - [Viewing your codes](#viewing-your-codes)
  - [Insert into message editors](#insert-into-message-editors)
  - [Use with Scanner](#use-with-scanner)
- [Troubleshooting](#troubleshooting)
  - [The placeholder wasn't replaced with a TOTP](#the-placeholder-wasnt-replaced-with-a-totp)
  - [My placeholder gets replaced with the TOTP code in Repeater](#my-placeholder-gets-replaced-with-the-totp-code-in-repeater)
- [Settings](#settings)
  - [Save TOTPs to project file](#save-totps-to-project-file)
  - [Use regex when matching TOTPs](#use-regex-when-matching-totps)
  - [Enable verbose logging](#enable-verbose-logging)
- [Acknowledgements](#acknowledgements)

## Features
- TOTP codes are refreshed automatically and displayed right in Burp Suite
- Automatically insert TOTPs into requests sent from any Burp tool using a simple or regex match string
  - Use with Burp's Scanner to allow crawling websites with two-factor authentication
  - Use with Repeater to test authentication flows without constantly pasting TOTP codes
  - Enable and disable matching for each TOTP on the fly
- Add TOTPs from QR codes, no manual entry required
- Save TOTPs to your project file
- Add TOTPs with custom durations, code lengths, and choose which hashing algorithm to use (SHA-1, SHA-256, or SHA-512)
- Copy TOTPs to your clipboard with one click
- Insert TOTP codes into message editors from the right-click (context) menu
- Name each TOTP to distinguish them

## Installation
1. Download the source code
2. Build the extension using `./gradlew build` (Mac & Linux) or `.\gradlew.bat build` (Windows)
3. Launch Burp Suite and navigate to the "Extensions" tab
4. Click "Add"
5. Set "Extension type" to `Java`
6. Select the Jar file you built in Step 2 (It will be in `./build/libs/TOTP.jar`)
7. Click "Next" to load the extension

For more information, see [Installing extensions manually](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/installing/manual-install) from PortSwigger.

## Usage

### Adding a code
Navigate to the "TOTP" tab in Burp Suite. At the top, there is a form allowing you to enter the details of a TOTP.

#### Name
Give your TOTP a name! This will allow you to distinguish it from other TOTPs in the list.

#### Secret
This is where you will enter in the Base 32-encoded secret of your TOTP. Typically, the secret will be in the form `A2B3 C4D5 E6F7 GHIJ KLMN OPQR STUV WXYZ`. The extension uses the Base 32 encoding described in [Section 6 of RFC4648](https://datatracker.ietf.org/doc/html/rfc4648#section-6), which includes the uppercase letters A-Z and digits 2-7.

#### Duration
This is how long each TOTP lasts for, in seconds. This will almost always be 30 seconds, but some applications may use values such as 60 seconds.

#### Code Length
The number of digits that generated codes should be. This will almost always be 6, returning a code in the form of `123 456`. However, some applications may use values such as 8.

#### Algorithm
This allows you to select the hashing algorithm that the application expects. If you are unsure, this will almost always be SHA-1, which uses the HMAC-SHA-1 hash function. Some applications may use SHA-256 or SHA-512 hashing instead.

### Scanning QR Codes
QR codes can be used to automatically populate the values detailed in [Adding a code](#adding-a-code). You may paste a QR from your clipboard or scan one that is on your screen. See below for details. See [Acknowledgements](#acknowledgements) for information about the URI specification used.

#### Scan QR
This will scan a QR code that is on your screen. In order for QR codes to be scanned, you must have the code and Burp visible on the same monitor. Depending on your operating system, you may also have to give Burp Suite access to take a screen capture. If a QR code is successfully scanned, the encoded values will be added to their respective fields. Adjust them or simply press "Add."

#### Paste QR
This button will take an image from your clipboard and scan it for a QR code. Alternatively, if you have the encoded URI (the contents of a TOTP QR code) in the form of `otpauth://...` on your clipboard as text, the extension will use that.

### Setting your Scope
The extension allows you to define a scope that limits which requests it will replace in. The scope that you configure in this dialog will not affect [session handling rules](#session-handling-rules).

![The scope configuration dialog in the extension](/images/Scope%20Configuration.png)

#### Tools scope
The extension will only monitor requests from the tools you enable here.

#### URL scope
You may either choose to include all URLs, use the suite scope, or define a custom scope. The custom scope is configured by defining prefixes, such that the extension will listen to all requests with URLs that start with your prefix. Scopes that start with `https://` will only allow HTTPS requests to be in scope. However, scopes that start with `http://` or that omit a protocol work for any protocol at the given URL.

##### Include subdomains?
Enabling this will allow subdomains of that prefix to be included in the scope. For example, `github.com` with "Include subdomains?" enabled will also match `example.github.com`.

### Session handling rules
You can also invoke the extension with a session handling rule if you prefer to control the scope that way. When configuring a rule, click "Add" > "Invoke a Burp extension" then select "Insert TOTP into request." See [Session handling rule editor](https://portswigger.net/burp/documentation/desktop/settings/sessions/session-handling-rules) to learn more.

### Viewing your codes
In the "TOTP" tab, you can see a list of all of the TOTPs you have added to this project.

#### Name
Shows the name you assigned to this TOTP.

#### Algorithm
Displays the algorithm you assigned to this TOTP.

#### Code
The current, valid TOTP code will be displayed with a space in the middle for readability. This code will be updated according to the duration you configured.

#### Progress Bar
A progress bar will display next to the code indicating the amount of time remaining before the code will be invalid. It will count down each second from the number of seconds you configured in the [duration](#duration).

#### Match Field
Here, you can enter the string that you want the extension to search for in requests. If you would like to use regex, see [Use regex when matching TOTPs](#use-regex-when-matching-totps). When the extension handles an [in-scope request](#setting-your-scope), it will replace all occurrences of this match string with your TOTP. It will also update the Content-Length header of the request, if appropriate. 

#### Replace in requests?
This checkbox allows you to quickly enable or disable replacing for that specific TOTP. When disabled, the match string cannot be edited and the extension will not replace occurrences of the match in requests. If you have a lot of TOTPs saved, you may find better performance by disabling matching of TOTPs that you are not using.

#### Copy code (Shield with lock)
This button will copy the current TOTP code to your clipboard.

#### Copy secret (Key)
This button will copy the TOTP's `otpauth://` URI to your clipboard, containing all of the details of your TOTP. You may paste the URI right back into the extension using the [Paste QR](#paste-qr) button.

#### Remove (X)
This button will remove the TOTP from the extension. It will also remove it from the project storage if the [Save TOTPs to project file](#save-totps-to-project-file) option is enabled.

### Insert into message editors
Right click in any editable message editor in Burp. Under `Extensions > TOTP` you can either insert the current code for each TOTP you have saved or insert the match string placeholder you have configured. This menu will not display if you have no codes saved in the extension.

### Use with Scanner
The extension can be used with Burp's Scanner, which allows you to scan targets that use TOTPs for multi-factor authentication. 

1. Record a login sequence for your application, entering the TOTP as normal when prompted. [See PortSwigger's documentation for more information](https://portswigger.net/burp/documentation/scanner/authenticated-scanning/using-recorded-logins).
2. Once you paste in your script from the Navigation Recorder, click "See as Events"
3. In the list, select the event where you entered your TOTP and click "Edit"
4. In the "Typed Value" section, enter the placeholder you set for the desired TOTP. See [Match Field](#match-field) for more information.
5. Click "OK."
6. Test if the replacement works by clicking the "Replay" button. You will see the browser enter your placeholder (e.g. `_Name_`) in the box, but the request will be modified by the extension before it is sent. You can verify this by checking the "Logger" tab and examining the request.

## Troubleshooting

### The placeholder wasn't replaced with a TOTP
[Check your scope](#setting-your-scope)! Make sure the tool that you are using is selected. If you are using a session handling rule, try using the [session handling tracer](https://portswigger.net/burp/documentation/desktop/settings/sessions#:~:text=rule%20editor%20documentation.-,Session%20handling%20tracer,-The%20session%20handling).

### My placeholder gets replaced with the TOTP code in Repeater
This is how Burp handles session handling rules. If you don't want this to happen, consider not using a session rule and [configuring your scope through the extension](#setting-your-scope) instead.

## Settings
You can find options for this extension in Burp's application settings under the "Extensions" tab.

### Save TOTPs to project file
Enabling this will store the settings for each TOTP you add in the storage of your project file. This means TOTPs persist, even when you restart Burp Suite. The [scope you define](#setting-your-scope) will always be saved to the project file regardless of this setting.

**Security Note**:  This setting stores the secrets of your TOTPs in your `.burp` project file. If you are concerned about the security of this, consider disabling this option or use care when sharing your project file.

### Use regex when matching TOTPs
Enabling this option will treat your match strings as regular expressions according to [Java Pattern syntax](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/regex/Pattern.html).

### Enable verbose logging
This option enables additional logging for debugging purposes. This can affect performance, and should be left off when it is not in use.

## Acknowledgements
- TOTPs are generated using code from [RFC 6238 Appendix A](https://datatracker.ietf.org/doc/html/rfc6238#appendix-A) by Johan Rydell, published under the IETF Trust's Revised BSD License.
- QR code scanning is done using the [ZXing](https://github.com/zxing/zxing) library, which is licensed under the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0.html).
- There is no official standard for the OTP Auth URI format (`otpauth://`.) However, this extension follows [this draft specification by I. Y. Eroglu](https://linuxgemini.github.io/otpauth-spec-draft/).
- This extension uses the [Templarian/MaterialDesign](https://github.com/Templarian/MaterialDesign) icon pack with [kordamp/ikonli](https://github.com/kordamp/ikonli) for icons. 