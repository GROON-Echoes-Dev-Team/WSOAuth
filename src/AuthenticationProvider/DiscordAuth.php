<?php
namespace AuthenticationProvider;

use \MediaWiki\Auth\AuthManager;
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
class DiscordAuth implements \AuthProvider
{

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
        if (!isset($returnToQuery)) {
            // TODO Better error messages
            return false;
        }
        // TODO Parse url instead of exploding
        $exploded_query = explode("=",$returnToQuery);

        if(count($exploded_query) != 3){
            $to_str = json_encode($exploded_query);
            return false;
        }

        $code = trim($exploded_query[2]);
        if(!$code){
            return false;
        }

        // TODO Import these via secrets file
        $url = 'https://discord.com/api/oauth2/token';
        $key = '748478733077315645';
        $secret = 'TODO';

        //The data you want to send via POST
        // TODO Do we want more data
        $fields = [
            'client_id'      => $key,
            'client_secret' => $secret,
            'grant_type'         => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'https://localhost/wiki/index.php?title=Special:PluggableAuthLogin',
            'scope' => 'email identify'
        ];

        // TODO Pull to function
        //url-ify the data for the POST
        $fields_string = http_build_query($fields);

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch,CURLOPT_URL, $url);
        curl_setopt($ch,CURLOPT_POST, true);
        curl_setopt($ch,CURLOPT_POSTFIELDS, $fields_string);

        //So that curl_exec returns the contents of the cURL; rather than echoing it
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, true); 

        //execute post
        $result = curl_exec($ch);
        if(!$result){
            return false;
        }
        $result_json = json_decode($result);
        if(array_key_exists('error', $result_json)){
            return false;
        }
        // TODO Persist refresh token?
        $token = $result_json->access_token;
        // TODO ensure token isn't logged and is secure


        $discord_user = new DiscordClient([
            'token' => $token,
            'tokenType' => 'OAuth'
        ]); 

        $user = $discord_user->user->getCurrentUser();

        $user_str = json_encode($user);

        // TODO Function
        // TODO token from secret file
        $discord = new DiscordClient([
            'token' => 'TODO'
        ]); 

        // TODO Check goon role is assigned
        // TODO Extract guild id to config, setup new bot in real server with Wiki name

        $roles = $discord->guild->getGuildRoles(['guild.id' => 748488398104428558]);
        $role_id_to_name_map = array();
        foreach ($roles as $role) {
            $role_id_to_name_map[$role->id] = $role->name;
        }
        $member = $discord->guild->getGuildMember(['guild.id' => 748488398104428558, 'user.id' => $user->id]);
        $username = $member->user->username;
        foreach ($member->roles as $user_role_id) {
            $role_name = $role_id_to_name_map[$user_role_id];
        }


        // TODO Better way for username?
        $unique_username = $user->username  . $user->discriminator;


        // TODO Persist user id, real discord name, etc in a better manner
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

}