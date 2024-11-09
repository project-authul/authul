# Authul: The Customer Identity Management System You Never Knew You Wanted

Here's the story: you've got something on The Web -- a website, application, whatever -- that needs authentication.
A simple username/password box might work, and that's easy enough to make, but these days, a username/password doesn't cut it.
You need to support MFA, or the whole Internet will point and laugh.
Five minutes after you launch, someone wants to login with HubLab or Qbook, and a week later you're on [SSO.tax](https://sso.tax) because you don't support Enterprise SSO Integration, and now passkeys are a thing, and... OH MY GOD THERE'S SO MUCH THAT NEEDS DOING.

Plus, even that "simple" username/password box isn't so simple.
There's password recovery, the need to securely hash everything, avoiding all manner of security embarrassments (who even *knows* what a timing oracle is?), and heaven knows what else.

It's all very complicated.

So, you think "I know!  I can outsource this!  There are heaps of companies that do managed auth!"
Well, sure, you *can*, and more power to you, but what if you really, *really* don't want to?

There are open source Customer Identity Management (CIM) systems out there, but -- having tried to install and use several of them -- they're all painful.
Most are "open core", that hide all the goodies away, or even require you to sign up to their "platform" (wait, weren't we supposed to be self-hosting?) to actually use them.
The few that are left are, to put it bluntly, hideous monstrosities that are difficult to install, manage, and upgrade, and don't appear to have been built with even the faintest notion of security.

Which is why I decided to create Authul.

Yes, it rhymes with "awful".

That's no accident.
I've spent far too long staring at OAuth specs while building this.


# Sold Already?

Great.
[The Authul book](https://authul.com/book) will give you everything you need to know.

If you still need more details, read on.


# What Authul Does

Authul is a web application whose entire purpose is to provide centralised authentication for websites, web applications, and APIs.
It provides a single place for users to register, sign in, and obtain tokens which can then be used to authenticate requests to other services.

Websites and web applications can use Authul to provide login and authentication functionality that is secure and implements all the modern features and authentication methods, such as passkeys, social logins, Enterprise SSO, and so on.
They do this by interacting with Authul as an OpenID Connect (OIDC) Relying Party (RP), with Authul acting as the Identity Provider (IdP).

Users register themselves with Authul, and can choose to authenticate themselves with any one (or more) of a number of different mechanisms.
When the website wants a user to login, they redirect the user to the Authul server, which verifies that the user is who they say they are, and then returns an ID token to the website, proving that the user is authenticated.

What Authul provides is a secure, low-maintenance alternative to coding a user registration system into the web application itself.
Rather than writing a bespoke login page, and all the behind-the-scenes stuff that implies, like password changes, MFA handling, and so on, you instead delegate all that to Authul.


## Is Authul an SSO Provider?

Authul *can* be considered a kind of Single Sign-On (SSO) provider, in the sense that multiple websites, web applications, and APIs can use a single Authul instance to authenticate users.
A user who visits each of those websites does not need to separately authenticate to each one; the website will send the user to Authul, asking "is this user authenticated?", and Authul will immediately return an authentication token to the website if the user has recently authenticated themselves to Authul.

However, what is typically referred to as "SSO" is more about an organisation provisioning a closed set of users and then allowing those users to access a wide variety of different sites on behalf of the organisation.
The SSO provider acts as a directory of sorts, and often includes other directory services, such as LDAP, as part of the package.

Authul, in contrast, is about authenticating an open set of users (eg "anyone who visits my website"), to a relatively small set of websites, APIs, etc.

If you need single sign-on for a closed set of users, especially against a broad variety of applications and services you don't fully control, then Authul is not the solution for you.
Instead, check out [Kanidm](https://kanidm.com/), which is an SSO provider and directory service with similar principles to Authul, but targeted at the "closed set of users accessing a wide variety of different sites" demographic.


# The Authul Philosophy

If you need some way to authenticate users on your web property, and the following goals resonate, then Authul is probably going to be a good fit.

## Secure... Always

Everything built in Authul is designed and implemented to be secure, as far as the underlying protocols allow.
If there is an insecure way to do something, we won't do it.
If something we've done is later found to be insecure, we'll rip it out (with a migration path *if possible*, but no guarantees).
There are no "make me less secure" configuration options.

As an example, take OAuth2 (please!).
The specification, and its many offspring (such as OpenID Connect) have many different ways of doing much the same thing.
Authul only implements the more secure available variants of each element of the overall OAuth2 protocol.
So to fetch a token, for example, you *must* use the Authorization Code flow, with PKCE, and authenticating with a signed JWT (rather than a client secret), because that is the least-worst available option.


## Easy to Administer

Ain't nobody got time to faff around with complex installation instructions -- even (especially!) the Authul devs.
Which is why Authul is hella simple to install and run, with extensive documentation and sensible defaults.

There are rather a lot of possible config options, because that be how authentication protocols be, but all configuration is done via environment variables, so it's easy to configure and deploy in Cloud-native environments.

The only required external dependencies that Authul has is a [PostgreSQL database](https://postgresql.org) and the ability to run a single Rust binary on the Internet.
Upgrading Authul should always be as simple as dropping a new binary in place, stopping the old one, and starting the new one.


## Always Free Software

We don't do "open core", and we don't do non-compete licencing.
Authul is a contribution to the notional "software commons", where everyone is free to use, study, and share the software.
The only requirement is that any enhancements you make must be offered back to the software commons, so that others may benefit as way you have benefited.

There are [commercial support options available](#commercial-support), but these services do not give you access to additional Authul features or licencing options.
Instead, they serve as a way for organisations to get guarantees around feature development and access to knowledgeable professional support.


# Where To Go From Here

Start reading [the Authul book](https://authul.com/book) for everything you want to know about installing, configuring, and using Authul.

If you wish to contribute to Authul in some way, whether that be with bug reports, vulnerability reports, feature requests, or improvements, please see [our contribution guide](./CONTRIBUTING.md).


# Commercial Support

The following organisations are willing to provide commercial support options for Authul.
While they may employ Authul contributors, they are not formally associated or affiliated with the Authul project or its contributors in general.

* [Tobermory Technology](https://tobermorytech.com)


# Licencing

Except as otherwise indicated, all content in this repository is covered by the following licencing notice.

    Copyright (C) 2024 Matt Palmer <matt@authul.com> and the Authul Contributors.

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU Affero General Public License version 3, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
