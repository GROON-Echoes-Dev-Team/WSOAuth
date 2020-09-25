# Overview

Goosefleet's wiki is currently publicly accessible. Ideally only corp members should be able to view and edit it. The Goosefleet discord server is where members authenticate to join the corp and is the source of truth for who is a Goosefleet member or not, so ideally the Wiki should defer to the discord server on who to let in or not.

Mediawiki doesn't come with any ready to go plugin which integrates with the authentication mechanisms Discord provide. However the plugin [WSOAuth](https://www.mediawiki.org/wiki/Extension:WSOAuth) provides scaffolding for a OAuth2 based authentication flow and the [ability to create](https://www.mediawiki.org/wiki/Extension:WSOAuth/For_developers) a custom Authentication provider which I have done here. This repo is a fork of WSOAuth with the only change being the addition of a custom Authentication Provider which works with discord found in src/AuthenticationProvider/DiscordAuth.php.

## How it works

Discord explains how to use their OAuth2 authentication flow for you own applications [here](https://discord.com/developers/docs/topics/oauth2). Put simply this is what will happen when a goon accesses wiki.goosefleet.cx with this extension installed.

1. They are redirected to discord.com to confirm they are happy to give the wiki access to their discord user id and email address.
2. Once they confirm they are sent back to a special page on the wiki with an access token in the url.
3. The wiki then uses this access token to request a user token from discord's token rest API.
4. This user token is then used by the wiki to access discord's user API to get the users ID and email.
5. Using the user's id the wiki then uses separate credentials for a bot with access to view members and roles on Goosefleet's discord to lookup that users roles in Goosefleet.
6. Then it compares the users discord roles against a list of discord roles configured in mediawiki to be allowed to access the wiki. 
7. Finally if the user has one of the valid roles they are logged into the wiki and can edit and view it, otherwise they are shown an error.

# Setup Instructions

## Pre-Requisites 

* composer from [here](https://getcomposer.org)  to install this extension's php dependencies. This is probably already installed on your mediawiki server.
* git and the ability to clone directly from github to download and update the extensions.

## Setup a bot with access to view members and roles in Goosefleet discord

1. Follow [these instructions](https://discordpy.readthedocs.io/en/latest/discord.html), you need manage server permission on the discord server you whish to add the bot to. You do not need OAuth2 Code grant. In step 6 of inviting your bot it doesn't need any permissions ticked so make sure they are all unchecked.

## Backup the Wiki
Later on you will run a database update script. Also from now on everyone will be given new mediawiki accounts tied to their discord account and the old accounts people have made should become inaccessible. So make sure you take a comprehensive wiki backup of the database, LocalSettings.php and the extensions, or maybe even the entire mediawiki installation.

## Install Pluggable Auth 
In your mediawiki extensions folder run:
```
git clone git@github.com:wikimedia/mediawiki-extensions-PluggableAuth.git PluggableAuth 
cd PluggableAuth 
composer install
```

## Install this extension
In your mediawiki extensions folder run:
```
git clone git@github.com:GROON-Echoes-Dev-Team/WSOAuth.git WSOAuth
cd WSOAuth
composer install
``` 

## Configure this extension

Append the following to LocalSettings.php 
```
// Configure Discord Authentication 

// Load the extensions
wfLoadExtension( 'PluggableAuth' );
wfLoadExtension( 'WSOAuth' );

// Disable normal account creation and block unauthenticated users from viewing and editing the wiki.
$wgGroupPermissions['*']['autocreateaccount'] = true;
$wgGroupPermissions['*']['read'] = false;
$wgGroupPermissions['*']['edit'] = false;
$wgGroupPermissions['*']['createaccount'] = false;

// Instead of having to click login immediately start the discord auth process when someone visit's the wiki.
$wgPluggableAuth_EnableAutoLogin = true;
$wgPluggableAuth_EnableLocalLogin = false;

// Enable the custom Discord authentication provider.
use AuthenticationProvider\DiscordAuth;
$wgOAuthCustomAuthProviders = [
    'discord' => DiscordAuth::class 
];
$wgOAuthAuthProvider = 'discord';

// Configure the discord authentication provider.
$wgOAuthDiscordOAuth2Url = "TestAuthUrl";
$wgOAuthDiscordBotToken = "TestBotToken";
$wgOAuthDiscordGuildId = 10023;
$wgOAuthDiscordAllowedRoles = array("AllowedRoleOne");
$wgOAuthDiscordClientId = "TestClientId";
$wgOAuthDiscordClientSecret = "TestClientSecret";
$wgOAuthDiscordRedirectUri = 'https://wiki.goosefleet.cx/wiki/index.php?title=Special:PluggableAuthLogin';

```

## Run database update script

Run in your mediawiki install location:
```
php ./maintenance/update.php
```

# Original WSOAuth REAME

![PHP Lint](https://github.com/WikibaseSolutions/WSOAuth/workflows/PHP%20Lint/badge.svg)

The **WSOAuth** extension enables you to delegate authentication to an OAuth provider. It provides a layer on top of PluggableAuth to allow authentication via a number of OAuth providers.

This extension requires PluggableAuth to be installed first. It also requires some PHP libraries, which may be installed using Composer.

Additional information about the extension and how to use it can be found on it's [MediaWiki page](https://www.mediawiki.org/wiki/Extension:WSOAuth).
