<?php

declare(strict_types=1);

/*
 * Autoloader für die gebündelten Bibliotheken:
 *  - php-opcua/opcua-client v4.6.0 (MIT)  → libs/opcua-client
 *  - psr/log, psr/simple-cache, psr/event-dispatcher (MIT) → libs/psr-*
 * Wird nur aktiv, wenn eine Klasse noch nicht geladen ist – andere Module,
 * die dieselben PSR-Interfaces mitbringen, kollidieren daher nicht.
 */
if (!defined('OPENOPCUA_AUTOLOAD')) {
    define('OPENOPCUA_AUTOLOAD', true);
    spl_autoload_register(static function (string $class): void {
        static $map = [
            'PhpOpcua\\Client\\'     => __DIR__ . '/opcua-client/',
            'Psr\\Log\\'             => __DIR__ . '/psr-log/',
            'Psr\\SimpleCache\\'     => __DIR__ . '/psr-simple-cache/',
            'Psr\\EventDispatcher\\' => __DIR__ . '/psr-event-dispatcher/',
        ];
        foreach ($map as $prefix => $dir) {
            if (strncmp($class, $prefix, strlen($prefix)) === 0) {
                $file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
                if (is_file($file)) {
                    require $file;
                }
                return;
            }
        }
    });
}
