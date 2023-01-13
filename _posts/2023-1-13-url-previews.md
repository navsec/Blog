---
title: "URL Previews - Detecting Incident Responders"
date: 2023-1-13
---

It's common training that responders should be careful when clicking or navigating to any URL involved in an incident, not only because of the inherent danger but also to avoid generating an access log entry. An attacker is likely to be actively monitoring access logs for their callback infrastructure during a campaign. These access logs provide valuable information through positive confirmation that their payload was successful or that their infrastructure is being examined.

While monitoring these logs, an attacker may end up seeing unusual HTTP requests from ranges belonging to large companies (Microsoft, Apple, etc) with bot-like user agents. These abnormal and unexpected requests can be related to URL previews. Many chat applications or real time messaging platforms will detect when a valid URL is sent in a chat and will do some work in the background to enrich the message.

Sometimes the bot will retrieve basic information from the site such as as the site title or HTML head data and show that info in a preview window within the chat app so that users have more information before clicking a link. In order to do that - it has to make an HTTP request to the site which generates an entry in that site's access log, often times with a unique user agent matching the specific service.

Some chat applications don't provide message previews but still appear to examine the URL. There are a variety of reasons as to why these applications do this, but I theorize they are likely related to data scraping for analytic purposes or content inspection to make sure known malicious links aren't being shared over the platform.

Some applications may offload the HTTP request for URL previews to the client and other applications appear to have dedicated services that makes these HTTP requests and relay information back to the client. This means that the source IP in access logs may be from the client's network or from a range owned by the application provider depending on the application.


During a incident, responders are likely collecting and documenting any URLs that are being used by the attacker. Depending on the severity of the incident, responders may also use out-of-band channels to ensure that their communication is not compromised. If improperly defanged URLs are shared in a chat - the application may attempt to perform a URL preview which an attacker can use to infer that their being talked about / and even leak over what communication platform the responders are using.

For demonstration purposes, I've compiled a small list of how different chat applications handle URL previews to demonstrate how this would work.

Sharing a URL in discord - there is no visual indication that a URL preview was generated unlike other chat applications.
![Image](/images/2023-1-13-url-previews.md/Pasted image 20230113003849.png)

However, we do observe an incoming request from Discord hit our web service.
![Image](/images/2023-1-13-url-previews.md/Pasted image 20230113003917.png)

Sharing a URL in Teams
![Image](/images/2023-1-13-url-previews.md/Pasted image 20230113154705.png)

Interesting enough, the user-agent included in this one is for SkypeUriPreview. Microsoft looks to be reusing the same URL preview service for Skype within Microsoft teams as well.
![Image](/images/2023-1-13-url-previews.md/Pasted image 20230113155036.png)

Sharing a URL in Steam messages - Just for fun :)
![Image](/images/2023-1-13-url-previews.md/![[Pasted image 20230113155503.png)

Steam actually makes two requests, one for HEAD and then another to retrieve more information
![Image](/images/2023-1-13-url-previews.md/![[Pasted image 20230113155601.png)

![Image](/images/2023-1-13-url-previews.md/![[Pasted image 20230113155621.png)

It is crucial to always sanitize/disarm/defang URLs before sharing them internally. If an operator is monitoring logs and sees abnormal bot hits - its a strong indication that they are being talked about / watched and an attacker might alter their behavior or accelerate their plans if they believe they are on the clock.

Responders may be able to use this to their advantage by spoofing a user agent for something that an attacker may already be expecting to see hit their web server. For example, if the delivery method was email - it might not raise alarm bells for the attacker to see supposed url preview requests coming from O365 or Microsoft ranges. The attacker might have a resonable expectation that some form of URL inspection/sandboxing is to be expected. This might allow responders a better opportunity to analyze the callback site or collect samples without tipping off the attacker as long as the request can be originated from a reasonable range.





