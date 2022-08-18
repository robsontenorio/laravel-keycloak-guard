<?php

const CONFIG_FILE = '.php-cs-fixer.config';
const CONFIG_URL = 'https://raw.githubusercontent.com/atabix/code-style/main/php-cs-fixer.config.php';
const CACHE_MINUTES_TTL = 60;

if (Cache::expired(CONFIG_FILE, CACHE_MINUTES_TTL)) {
    Cache::download(CONFIG_URL, CONFIG_FILE);
}

return require CONFIG_FILE;

class Cache
{
    public static function expired($file, $minutes = 5)
    {
        $isValid = \file_exists(rtrim(__DIR__, '/') .'/'. $file) && (\filemtime(rtrim(__DIR__, '/') .'/'. $file) > (\time() - 60 * $minutes));

        return ! $isValid;
    }

    public static function download($url, $file)
    {
        $contents = \file_get_contents($url);
        \file_put_contents(rtrim(__DIR__, '/') .'/'. $file, $contents, LOCK_EX);

        return 0;
    }
}