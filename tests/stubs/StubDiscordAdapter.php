<?php

declare(strict_types=1);


 final class StubDiscordAdapter implements \AuthenticationProvider\DiscordAdapter {

    public $userRoles = array();
    public $expectedAccessToken = '';

    public function getUser($userToken){
        if($userToken != $this->expectedAccessToken){
            throw Exception("Invalid Access Token provided to discord.");
        }
        $user = new StubUser();
        $user->discriminator = 1234;
        $user->id = 1;
        $user->username = "TestUserName";
        $user->email = "test@google.com";
        return $user;
    }

    public function getServerRolesForUser($user, $botToken, $guildId){
        return $this->userRoles;
    }

 }

 final class StubUser {

 }