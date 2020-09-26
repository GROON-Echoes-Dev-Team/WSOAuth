# Overview

Goosefleet's wiki is currently publicly accessible. Ideally only corp members should be able to view and edit it. The Goosefleet discord server is where members authenticate to join the corp and is the source of truth for who is a Goosefleet member or not, so ideally the Wiki should defer to the discord server on who to let in or not.

Mediawiki doesn't come with any ready to go plugin which integrates with the authentication mechanisms Discord provide. However the plugin [WSOAuth](https://www.mediawiki.org/wiki/Extension:WSOAuth) provides scaffolding for a OAuth2 based authentication flow and the [ability to create](https://www.mediawiki.org/wiki/Extension:WSOAuth/For_developers) a custom Authentication provider which I have done here. This repo is a fork of WSOAuth with the only change being the addition of a custom Authentication Provider which works with discord found in src/AuthenticationProvider/DiscordAuth.php.

## List of changes made to WSOAuth by thejanitor
The following files have been added:
* [DiscordAuth.php](https://github.com/GROON-Echoes-Dev-Team/WSOAuth/blob/master/src/AuthenticationProvider/DiscordAuth.php)
* [RealDiscordAdapter.php](https://github.com/GROON-Echoes-Dev-Team/WSOAuth/blob/master/src/AuthenticationProvider/RealDiscordAdapter.php)

No existing WSOAuth files have been changed, perhaps I have reformatted one or two however.

Additionally I threw away the existing unit tests as they were useless and added a small set of my own. These are currently hard to read and understand but will be refactored to something nicer soon.

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
2. Make note of your applications Client ID and Client Secret for configuring LocalSettings.php later.
3. Make note of the applications bot secret for configuring LocalSettings.php later.

## Backup and stop the Wiki
Later on you will run a database update script. Also from now on everyone will be given new mediawiki accounts tied to their discord account and the old accounts people have made should become inaccessible. So make sure you take a comprehensive wiki backup of the database, LocalSettings.php and the extensions, or maybe even the entire mediawiki installation.

Stop the wiki for now as we'll be making changes to it's configuration.

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

Append the following to LocalSettings.php and follow the instructions in the comments to configure the variables correctly.
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
// TODO configure the below variables!

// Follow these steps to configure this variable:
// - Go to your discord application and click on OAuth2. 
// - Add a redirect uri of "https://wiki.goosefleet.cx/wiki/index.php?title=Special:PluggableAuthLogin" without quotes. This has to match the configuration parameter $wgoOAuthDiscordRedirectUri below.
// - Select the redirect url you added in the prior step.
// - Select the identify and email scopes.
// - Hit copy next to the url at the bottom and replace the word REPLACEME in the quotes below with the copied url:
$wgOAuthDiscordOAuth2Url = "REPLACEME";

$wgOAuthDiscordBotToken = "REPLACE WITH BOT TOKEN";
// Already populated with goosefleet discord's guild id, replace if you wish to use a different server.
$wgOAuthDiscordGuildId = 747575380436713583;
// Assuming we want to use this existing Goosefleet role to control wiki access
$wgOAuthDiscordAllowedRoles = array("Fleet Member");
$wgOAuthDiscordClientId = "REPLACE WITH YOUR DISCORD APPLICATIONS CLIENT ID";
$wgOAuthDiscordClientSecret = "REPLACE WITH YOUR DISCORD APPLICATIONS CLIENT SECRET";
// I believe the URL below should be correct for goosefleet. However this might not be true due to apache rewrites etc.
$wgOAuthDiscordRedirectUri = 'https://wiki.goosefleet.cx/wiki/index.php?title=Special:PluggableAuthLogin';

```

## Run database update script

Run in your mediawiki install location:
```
php ./maintenance/update.php
```

## Restart the wiki and Test 

After the update start the wiki back up, confirm that when you visit it you are sent to discord, approving on the discord page should now return you to the wiki logged in as DiscordUsername + DiscordDiscriminator. You might be sent back to discord again to click authorize a second time, i do not know why this happens currently.

# Original WSOAuth REAME

![PHP Lint](https://github.com/WikibaseSolutions/WSOAuth/workflows/PHP%20Lint/badge.svg)

The **WSOAuth** extension enables you to delegate authentication to an OAuth provider. It provides a layer on top of PluggableAuth to allow authentication via a number of OAuth providers.

This extension requires PluggableAuth to be installed first. It also requires some PHP libraries, which may be installed using Composer.

Additional information about the extension and how to use it can be found on it's [MediaWiki page](https://www.mediawiki.org/wiki/Extension:WSOAuth).
