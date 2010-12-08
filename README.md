# Convio SSO Authentication plugin for Melody and Movable Type #

This plugin provides an "dual-mode" authentication driver for for Melody and
Movable Type v4.x which works with [Convio's Single Signon Open API][] to
provide authentication services for both locally-created and Convio-created
user accounts.

When this plugin is installed and configured:

   * Users will be able to log in with either Melody/MT or Convio credentials
     seamlessly and without having to think

   * Each locally-created user can associate their account with a Convio
     account and, in most cases, this is done automatically

   * Each Convio-created user will have, upon logging in, a local user record
     automatically created for them_<sup>[1]</sup>_ and automatically
     associated with their Convio account.

   * Any profile information available in Convio will be used to provision or
     update the local user profile ensuring that your user's email addresses
     and other important data is always kept up to date.

_<sup>[1]</sup>_ - Regardless of the canonical authentication source,
Melody/MT mandate that *all* authenticated users be represented by at least a
"skeleton" local author record to act as a target for the granting of local
permissions, association with the user's created content and proper auditing
of their actions throughout application.

## REQUIREMENTS ##

This plugin has a few important prerequisites:

   * Melody (any version) or Movable Type 4.x
   * The Net::Convio perl module (included in distribution)
   * The REST::Client perl module (included in distribution)
   * Movable Type installations will also need the [Melody Compatibility Layer plugin](https://github.com/endevver/mt-plugin-melody-compat)
   * A Convio API Administrator account and associated credentials

## ABOUT CONVIO OPEN APIs ##

Convio Open APIs offer a large number of ways for developers to
programmatically interact with the Convio service as detailed in their bulging
350-page [Convio Open API Reference][], excerpted below:

   * **Address Book API**   

     The Address Book API provides access and management functions for
     TeamRaiser Address Books.

   * **Advocacy API**   

     The Advocacy API provides methods to query and report on Advocacy alerts
     and user interactions.

   * **Calendar Events API**   

     The Calendar Events API provides query access to Convio Calendar Events
     (TeamRaiser events are exposed separately through the TeamRaiser API).

   * **Constituent Management API**   

     The Constituent Management API supports multiple methods to create,
     update, and query user data in the Convio Constituent360 database.

   * **Donation Processing API**   

     The Donation Processing API allows you to extend and customize the online
     giving and payment processing capabilities of the Convio system.

   * **Single Sign-On API**   

     The Single Sign-On API provides methods to authenticate users and
     securely establish a logged-in session with the Convio server using API
     calls. These API methods support both Convio-as-master and
     Convio-as-client implementations allowing you to use either Convio or an
     external system as the master authentication service.

   * **TeamRaiser API**   

     The TeamRaiser API gives you the means to customize and extend the
     TeamRaiser application, the Participant Center and the web pages for
     TeamRaiser teams, companies, and participants. This API includes methods
     to:
       * record, query, manage, and search TeamRaiser Events,
       * manage TeamRaiser Teams,
       * manage Team, Company, and Personal web pages,
       * record, query and manage Gifts,
       * query and update Surveys,
       * create, send, query, and manage messages to TeamRaiser Participants
         and Contacts.

This plugin only utilizes the Single Sign-On API and Constituent Management
API to do its work.

[Convio's Single Signon Open API]:  http://open.convio.com/api/#single_sign_on_api

[Convio Open API Reference]: http://open.convio.com/api/apidoc/Convio_Open_API_Reference.pdf

## INSTALLATION ##

To install this plugin follow the instructions found on [this
page](http://tinyurl.com/easy-plugin-install) ***EXCEPT*** that the
`ConvioSSOAuth.pack` directory must be installed into the **`addons`**
directory and **not the `plugins`** directory. 

If you do not have an addons directory, you can simply create one in the root
of your Melody/MT directory (`$MT_HOME/addons`).

## CONFIGURATION ##

This plugin has a number of configuration directives that must be set
correctly in config.cgi/mt-config.cgi in order to operate. All of these are ***REQUIRED***:

   * **`AuthenticationModule`**   

     > Specifies the authentication module in use by Melody/MT. This normally
     defaults to `MT`. However, to enable this plugin, it must be set to
     `ConvioSSO`.

   * **`ConvioSSOCustomDomainURL`**   

     > The URL to your organization's official, custom (i.e. non-Convio)
     domain. This is the URL that provides the `/site/CRConsAPI` endpoint of
     the Convio API

   * **`ConvioSSOAuthHost`**   

     > The domain name of the Convio authentication server specified for use
     by the organization's account. This is usually either
     `secure2.convio.net` or `secure3.convio.net`

   * **`ConvioSSOClientID`**   

     > Your organization's Convio Client ID which can be found in your Convio
     control panel. This is usually a two-letter identifier which is often
     seen in the Convio authentication URLs, for example,
     `https://secure3.convio.net/CLIENTID/site/`

   * **`ConvioSSOAdminUsername`**   

     > The username of any Convio account in your organization that has API
     administrator permissions. Note that no such account exists by default.
     The API administrator permission is a special permission that must be
     granted. Please see Convio documentation for details on setting up such
     an account.

   * **`ConvioSSOAdminPassword`**   

     > The corresponding password of the API Administrator account

   * **`ConvioSSOAPIKey`**   

     > Your organization's public Convio API key which you can find in your
     Convio control panel.

   * **`ConvioSSOSecretAPIKey`**   

     > Your organization's secret Convio API key which you can also find in
     your Convio control panel if you are logged in as an administrator.

### Optional Configuration Directives ###

There are two configuration directives that are either optional or not
*currently* required:

   * **`ConvioSSOAuthDebug`**   

     > This directive enables a special debug mode useful for properly
     configuring the plugin with the correct Convio account data. This should
     not be left on in production as the data it produces could aid a
     malicious user in attacking your site and/or Convio account.

   * **`ConvioSSOAPIVersion`**   

     > This directive specifies the Convio API version for all transactions.
     Currently, the *only* valid value is `1.0` but this is provided for
     forward-compatiblilty.

### DEFAULT USER PERMISSIONS ###

Since Convio-created users will be added to the installation upon first login,
it's important to set the "newly created users" permissions properly.
Otherwise, you will see the following error:

> Our apologies, but you do not have permission to access any blogs within
> this installation. If you feel you have reached this message in error,
> please contact your Movable Type system administrator.

To do this, go to `System Overview > Users > Permissions` and click the link
titled "Grant permission to a user". On the subsequent screen, select the
"(newly created user)" option and grant that user at least one non-commenter
role on at least one blog.

## LIMITATIONS AND KNOWN ISSUES ##

A paramount design goal of this plugin was to provide a working authentication solution that was also universally effortless to use for both system administrators and completely non-technical end users.  For that reason, certain assumptions were made and constraints implemented to simplify matters.  These are areas for possible future development should they be desired.

   * Though it is believed that we fixed this issue, Convio sessions may time
     out. If that occurs, please let us know and we will see about adding a
     bug (`<img src="http://customconviodomain/site/PixelServer">`) to all
     pages to deal with the issue once and for all

   * There is not currently a mechanism for Convio-created users to recover or
     reset a Convio password through MT, although they can still use the
     facilities Convio provides for such functions.

   * There is no logging (to our knowledge) on the Convio side for activity in
     Movable Type. This can be done through Convio's API (`logInteraction`) if
     it's required.

   * The only way to prevent the association between a Convio account and a
     locally-created account is to log into Melody/MT with local credentials
     *without* an active Convio session

   * There is no facility for logging out of *only* Melody/MT and *not* Convio

   * Profile data is force synchronized from Convio to Melody/MT and there is
     no facility for configuring otherwise

## VERSION HISTORY ##

Full details can be found in the [commit logs](http://github.com/endevver/mt-auth-convio/commits/master) but briefly:

* 2010/12/01 - Initial public release of v1.0-beta

## HELP, BUGS AND FEATURE REQUESTS ##

If you are having problems installing or using the plugin, please check out
our general knowledge base and help ticket system at
[help.endevver.com](http://help.endevver.com).

## ACKNOWLEDGEMENTS ##

This plugin was commissioned by [Progress Now](http://progressnow.org).
Endevver is incredibly proud to have them as a client and to, in some small
way, help facilitate their mission through this plugin.

## LICENSE ##

This program is distributed under the terms of the GNU General Public License, version 2.

## COPYRIGHT ##

Copyright 2010, Endevver LLC. All rights reserved.