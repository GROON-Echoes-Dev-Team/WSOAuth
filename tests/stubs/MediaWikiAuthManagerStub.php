<?php

declare(strict_types=1);

namespace MediaWiki\Auth;

final class AuthManager
{
    private static $instance = null;

    private function __construct()
    {
        $this->data = array();
    }

    public static function singleton() : AuthManager
    {
        if (self::$instance == null) {
            self::$instance = new AuthManager();
        }

        return self::$instance;
    }

    public function getAuthenticationSessionData($key){
        return $this->data[$key];
    }

    public function setAuthenticationSessionData($key, $value){
        $this->data[$key] = $value;
    }
}
