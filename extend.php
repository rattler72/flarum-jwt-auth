<?php

use Flarum\Extend;
use Coldsnake\JwtAuth\JwtAuthController;

return [
    (new Extend\Routes('api'))
        ->get('/jwt-auth', 'coldsnake.jwt-auth', JwtAuthController::class),
];
