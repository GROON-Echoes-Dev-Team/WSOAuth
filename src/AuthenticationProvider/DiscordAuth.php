<?php

namespace AuthenticationProvider;

use MediaWiki\Auth\AuthManager;
use MediaWiki\Logger\LoggerFactory;
use HTTP_Request2;
use RestCord\DiscordClient;

const RETURNTOURL_SESSION_KEY = 'PluggableAuthLoginReturnToUrl';
const RETURNTOPAGE_SESSION_KEY = 'PluggableAuthLoginReturnToPage';
const RETURNTOQUERY_SESSION_KEY = 'PluggableAuthLoginReturnToQuery';
const EXTRALOGINFIELDS_SESSION_KEY = 'PluggableAuthLoginExtraLoginFields';
const USERNAME_SESSION_KEY = 'PluggableAuthLoginUsername';
const REALNAME_SESSION_KEY = 'PluggableAuthLoginRealname';
const EMAIL_SESSION_KEY = 'PluggableAuthLoginEmail';
const ERROR_SESSION_KEY = 'PluggableAuthLoginError';

/**
 * Class DiscordAuth 
 * @package AuthenticationProvider
 */
interface DiscordAdapter {

    public function getUser($userToken);

}

class RealDiscordAdapter implements DiscordAdapter {
    public function getUser($userToken){
        $discord_user = new DiscordClient([
            'token' => $userToken,
            'tokenType' => 'OAuth'
        ]);

        return $discord_user->user->getCurrentUser([]);
    }

}

class DiscordAuth implements \AuthProvider
{

    function __construct($httpAdapter = null, $discordAdapter = null)
    {
        if(!$httpAdapter){
            $this->httpAdapter = new \HTTP_Request2_Adapter_Socket();
        } else {
            $this->httpAdapter = $httpAdapter;
        }

        if(!$discordAdapter){
            $this->discordAdapter = new RealDiscordAdapter();
        } else {
            $this->discordAdapter = $discordAdapter;
        }

        $this->logger = LoggerFactory::getInstance('MyCoolLoggingChannel');
    }

    /**
     * Log in the user through the external OAuth provider.
     *
     * @param $key
     * @param $secret
     * @param $auth_url
     * @return boolean Returns true on successful login, false otherwise.
     * @internal
     */
    public function login(&$key, &$secret, &$auth_url)
    {
        $auth_url = $GLOBALS['wgOAuthDiscordOAuth2Url'];
        $key = $GLOBALS['wgOAuthDiscordClientId'];
        $secret = $GLOBALS['wgOAuthDiscordClientSecret'];
        return true;
    }

    /**
     * Log out the user and destroy the session.
     *
     * @param \User $user The currently logged in user (i.e. the user that will be logged out).
     * @return void
     * @internal
     */
    public function logout(\User &$user)
    {
    }

    /**
     * Get user info from session. Returns false when the request failed or the user is not authorised.
     *
     * @param $key
     * @param $secret
     * @param string $errorMessage Message shown to the user when there is an error.
     * @return boolean|array Returns an array with at least a 'name' when the user is authenticated, returns false when the user is not authorised or the authentication failed.
     * @internal
     */
    public function getUser($key, $secret, &$errorMessage)
    {
        // TODO Use a salt, how to generate salt? Check other impl
        $authManager = AuthManager::singleton();
        $returnToQuery = $authManager->getAuthenticationSessionData(
            RETURNTOQUERY_SESSION_KEY
        );
        $this->logger->debug("returnToQuery = " . $returnToQuery);
        if (!isset($returnToQuery)) {
            // TODO Better error messages
            $errorMessage = "Something went wrong with the redirect back from Discord, please send this error message to @thejanitor in Discord: returnToQuery Not Set. ";
            return false;
        }
        // TODO Parse url instead of exploding
        $exploded_query = explode("=", $returnToQuery);

        if (count($exploded_query) != 3) {
            $to_str = json_encode($exploded_query);
            $errorMessage = "Something went wrong with the redirect back from Discord, please send this error message to @thejanitor in Discord: Error Decoding returnToQuery. " . $to_str;
            return false;
        }
        

        $code = trim($exploded_query[2]);
        if (!$code) {
            return false;
        }

        // TODO ensure token isn't logged and is secure
        $token = $this->requestDiscordUserToken($key, $secret, $code, $errorMessage);
        if (!$token) {
            return false;
        }


        $user = $this->discordAdapter->getUser($token);

        $user_str = json_encode($user);

        $discord_bot_client = new DiscordClient([
            'token' => $GLOBALS['wgOAuthDiscordBotToken']
        ]);

        // TODO Check goon role is assigned
        // TODO Extract guild id to config, setup new bot in real server with Wiki name

        $roles = $discord_bot_client->guild->getGuildRoles(['guild.id' => $GLOBALS['wgOAuthDiscordGuildId']]);
        $role_id_to_name_map = array();
        foreach ($roles as $role) {
            $role_id_to_name_map[$role->id] = $role->name;
        }
        $member = $discord_bot_client->guild->getGuildMember(['guild.id' =>$GLOBALS['wgOAuthDiscordGuildId']  , 'user.id' => $user->id]);
        $username = $member->user->username;
        foreach ($member->roles as $user_role_id) {
            $role_name = $role_id_to_name_map[$user_role_id];
        }


        // TODO Better way for username?
        $unique_username = $user->username  . $user->discriminator;


        // TODO Persist user id, real discord_bot_client$discord_bot_client name, etc in a better manner
        // TODO How to logout?
        // TODO How to refresh roles by indivudual or admin or on timer? 
        // TODO What happens if role changes yet session exists?
        // TODO Add setup into dockerfile
        // TODO Figure out backup
        // TODO Figure out how to work mediawiki/oauth redirect etc with apache proxy on vps
        // TODO Go over other security options for mediawiki
        // TODO Import old wiki + main page
        // TODO Release
        // TODO Setup new scafolding
        // TODO Semantic plugin + other fun extensions
        return [
            'name' => $unique_username, // required
            'realname' => $user->id, // optional
            'email' => $user->email // optional
        ];
    }

    /**
     * Gets called whenever a user is successfully authenticated, so extra attributes about the user can be saved.
     *
     * @param int $id The ID of the User.
     * @return void
     * @internal
     */
    public function saveExtraAttributes($id)
    {
    }

    private function requestDiscordUserToken($key, $secret, $code, &$errorMessage)
    {
        // TODO Pull to function
        //url-ify the data for the POST
        $request = new HTTP_Request2(
            'https://discord.com/api/oauth2/token',
            HTTP_Request2::METHOD_POST,
            array('adapter' => $this->httpAdapter)
        );
        $request->addPostParameter([
            'client_id'     => $key,
            'client_secret' => $secret,
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => 'https://localhost/wiki/index.php?title=Special:PluggableAuthLogin',
            'scope'         => 'email identify'
        ]);

        try {
            $response = $request->send();
            if (200 == $response->getStatus()) {
                $body = $response->getBody();
                $result_json = json_decode($body);
                if (array_key_exists('error', $result_json)) {
                    return false;
                }
                return $result_json->access_token;
            } else {
                $errorMessage = 'Error asking Discord Server for user information. The response from Discord was: ' . $response->getStatus() . ' ' .
                    $response->getReasonPhrase();
                return false;
            }
        } catch (\Exception $e) {
            $errorMessage = 'Fatal Error asking Discord Server for user information: ' . $e->getMessage();
            return false;
        }
    }
}
