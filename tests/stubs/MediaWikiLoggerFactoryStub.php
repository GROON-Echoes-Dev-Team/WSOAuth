<?php

declare(strict_types=1);

namespace MediaWiki\Logger;

final class LoggerFactory 
{
    private static $instance = null;

    private function __construct($id)
    {
        $this->id = $id;
    }

    public static function getInstance($id)
    {
        if (self::$instance == null) {
            self::$instance = new LoggerFactory($id);
        }

        return self::$instance;
    }

    public function debug($message){
        print($this->id . ": " . $message . "\n");
    }
}
