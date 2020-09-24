<?php

namespace AuthenticationProvider;

interface DiscordAdapter {

    public function getUser($userToken);
    public function getServerRolesForUser($user, $botToken, $guildId);

}

class RealDiscordAdapter implements DiscordAdapter {
    public function getUser($userToken){
        $discord_user = new DiscordClient([
            'token' => $userToken,
            'tokenType' => 'OAuth'
        ]);

        return $discord_user->user->getCurrentUser([]);
    }

    public function getServerRolesForUser($user, $botToken, $guildId){
        $discord_bot_client = new DiscordClient([
            'token' => $botToken
        ]);

        $roles = $discord_bot_client->guild->getGuildRoles(['guild.id' => $guildId]);

        $role_id_to_name_map = array();
        foreach ($roles as $role) {
            $role_id_to_name_map[$role->id] = $role->name;
        }

        $member = $discord_bot_client->guild->getGuildMember(['guild.id' => $guildId  , 'user.id' => $user->id]);


        $role_names = array();
        foreach ($member->roles as $user_role_id) {
            $role_name = $role_id_to_name_map[$user_role_id];
            \array_push($role_names, $role_name);
        }
        return $role_names;
    }

}