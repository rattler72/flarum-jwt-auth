<?php

namespace Coldsnake\JwtAuth;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\Response\TextResponse;
use Zend\Diactoros\Response\RedirectResponse;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Claim\Validatable;
use Flarum\Api\Controller\CreateUserController;
use Flarum\User\Exception\PermissionDeniedException;
use Flarum\User\UserRepository;
use Flarum\Api\Client;
use Flarum\Http\Rememberer;
use Flarum\Http\SessionAuthenticator;
use Flarum\Foundation\Application;
use GuzzleHttp\Client as HttpClient;
use League\Flysystem\Adapter\Local;
use League\Flysystem\Filesystem;

class JwtAuthController implements RequestHandlerInterface
{
    /**
     * @var \Flarum\User\UserRepository
     */
    protected $users;

    /**
     * @var Client
     */
    protected $api;

    /**
     * @var SessionAuthenticator
     */
    protected $authenticator;

    /**
     * @var Rememberer
     */
    protected $rememberer;

    /**
     * @var Path
     */
    protected $path;

    /**
     * @var PublicPath
     */
    protected $public_path;

    /**
     * @var SiteUrl
     */
    protected $site_url;

    /**
     * @param Client $api
     * @param SessionAuthenticator $authenticator
     * @param Rememberer $rememberer
     */
    public function __construct(Client $api, SessionAuthenticator $authenticator, Rememberer $rememberer, UserRepository $users, Application $app)
    {
        $this->api = $api;
        $this->authenticator = $authenticator;
        $this->rememberer = $rememberer;
        $this->users = $users;
        $this->path = $app->storagePath();
        $this->public_path = $app->publicPath();
        $conf = app('flarum.config');
        $this->site_url = $conf['url'];
    }

    public function handle(Request $request): Response
    {
        $queryParams = $request->getQueryParams();

        app('log')->info('Query Params = '.var_export($queryParams, 1));
        $token = $queryParams['token'];
        $token = (new Parser())->parse((string) $token); // Parses from a string

        $headers = $token->getHeaders(); // Retrieves the token headers
        $claims = $token->getClaims(); // Retrieves the token claims

        app('log')->info('Headers = '.var_export($headers, 1));
        app('log')->info('Claims = '.var_export($claims, 1));

        $email = $token->getClaim('ema');
        $avatar = $token->getClaim('ava');

        // remove any sizing params
        $p = '?sz=';
        if (strpos($avatar, $p)){
            $avatar = substr($avatar, 0, strpos($avatar, $p));
        }

        // get user info from care central... find out role
        $httpClient = new HttpClient();
        $res = $httpClient->get('https://carecentral.nursenextdoor.com/api/simpleuser/'.$email.'/HGUWYDG2374g09mas');
        $body = $res->getBody()->getContents();
        $cc_user = json_decode($body);

        app('log')->info('User API response = '.var_export($cc_user, 1));
        app('log')->info('User Role = '.$cc_user->data->role_id);

        $accepted_role_ids = [1,5,6,7,10];
        if (!in_array($cc_user->data->role_id, $accepted_role_ids)) {
            app('log')->info('role is invalid!');
            throw new PermissionDeniedException('Invalid role.');
        }

        $u = $this->users->findByEmail($email);

        if ($u != null) {
            // logIn
            app('log')->info('Login');
            $userId = $u->id;
            $avatarAtt = $u->getAvatarUrlAttribute();

            $target = 'photo.jpg';
            $length = strlen($target);
            if ((empty($avatarAtt) || (substr($avatarAtt,0,4) === 'http')) && !empty($avatar) && (substr($avatar, -$length) === $target)){
                $httpClient = new HttpClient();
                try {
                    $res = $httpClient->request('GET', $avatar);
                    if ($res->getStatusCode() != 404 && $res->getStatusCode() != 500){

                        $contents = file_get_contents($avatar);
                        $user_dir = $this->path.DIRECTORY_SEPARATOR.'user'.DIRECTORY_SEPARATOR.$u->id;
                        $filename = 'profile_'.$u->id.'.jpg';
                        $fs = new Filesystem(new Local($user_dir));
                        $fs->put($filename,$contents);

                        //$profile_path = realpath($user_dir.DIRECTORY_SEPARATOR.$filename);
                        $public_url = 'user'.DIRECTORY_SEPARATOR.$u->id.DIRECTORY_SEPARATOR.$filename;

                        app('log')->info('Public Profile pic url = '.$public_url);

                        $avatar = $public_url;
                        $u->changeAvatarPath($avatar);
                        $u->save();
                    }
                } catch (RequestException $e) {
                    app('log')->info('Problem loading avatar: '.$e->getMessage());
                }
            }

            $session = $request->getAttribute('session');
            $this->authenticator->logIn($session, $userId);
        // $response = $this->rememberer->rememberUser($response, $userId);
        } else {
            // register
            app('log')->info('Register');

            if ((strpos($email, 'nursenextdoor.com') === false) && (strpos($email, 'sixfactor.com') === false)) {
                // throw new Exception('Not authorized.');
                throw new PermissionDeniedException('Invalid account domain.');
            }

            $iat = $token->getClaim('iat');
            $sub = $token->getClaim('sub');
            $jti = $token->getClaim('jti');
            $hash = md5(''.$sub.$iat);

            app('log')->info('Comparing...'.$hash.' = '.$jti);

            if ($hash == $jti) {
                // match!
                app('log')->info('Hash match!');
            }

            $data = new ValidationData(); // It will use the current time to validate (iat, nbf and exp)
            $data->setIssuer('https://carecentral.nursenextdoor.com/auth/jwt');
            $data->setId($jti);

            if ($token->validate($data)) {
                // check if the user is in the database
                $username = substr($email, 0, strpos($email, '@'));
                $username = preg_replace("/[^A-Za-z0-9 ]/", '', $username);
                $usernameExists = $this->users->findByIdentification($username);
                if ($usernameExists != null) {
                    $username = $username.rand(10, 99);
                }
                $password = $this->generateStrongPassword();
                $userdata = [
                    'username' => $username,
                    'email' => $email,
                    'password' => $password,
                    'isEmailConfirmed' => 1,
                    'avatarUrl' => $avatar,
                ];

                $controller = CreateUserController::class;
                // $actor = $request->getAttribute('actor');

                // use admin actor
                $actor = $this->users->findOrFail(1);
                $body = ['data' => ['attributes' => $userdata]];

                app('log')->info('Actor = '.var_export($actor, 1));
                app('log')->info('Body = '.var_export($body, 1));
            } else {
                app('log')->error('Invalid token');
                // if ($token->isExpired()) {
                //     app('log')->error('Expired token');
                // }

                $claims = [];
                foreach ($token->getClaims() as $claim) {
                    if ($claim instanceof Validatable) {
                        if (!$claim->validate($data)) {
                            app('log')->error('Failed: '.var_export($claim, 1));
                        }
                    }
                }

                throw new PermissionDeniedException('Invalid token.');
            }

            app('log')->info('Valid? = '.var_export($token->validate($data), 1));

            $response = $this->api->send($controller, $actor, [], $body);

            $body = json_decode($response->getBody());

            if (isset($body->data)) {
                $userId = $body->data->id;

                $user = User::find($userId);

                $target = 'photo.jpg';
                $length = strlen($target);
                if (!empty($avatar) && (substr($avatar, -$length) === $target)){
                    $httpClient = new HttpClient();
                    $res = $httpClient->request('GET', $avatar);
                    if ($res->getStatusCode() != 404 && $res->getStatusCode() != 500){

                        $contents = file_get_contents($avatar);
                        $user_dir = $this->path.DIRECTORY_SEPARATOR.'user'.DIRECTORY_SEPARATOR.$user->id;
                        $filename = 'profile_'.$user->id.'.jpg';
                        $fs = new Filesystem(new Local($user_dir));
                        $fs->put($filename,$contents);

                        //$profile_path = realpath($user_dir.DIRECTORY_SEPARATOR.$filename);
                        $public_url = 'user'.DIRECTORY_SEPARATOR.$user->id.DIRECTORY_SEPARATOR.$filename;

                        app('log')->info('Public Profile pic url = '.$public_url);

                        $avatar = $public_url;
                        $user->changeAvatarPath($avatar);
                        $user->save();
                    }
                }


                // log in as new user...
                $session = $request->getAttribute('session');
                $this->authenticator->logIn($session, $userId);

                $response = $this->rememberer->rememberUser($response, $userId);
            }
        }

        $response2 = new RedirectResponse('/');

        return $response2;
    }

    // Generates a strong password of N length containing at least one lower case letter,
    // one uppercase letter, one digit, and one special character. The remaining characters
    // in the password are chosen at random from those four sets.
    //
    // The available characters in each set are user friendly - there are no ambiguous
    // characters such as i, l, 1, o, 0, etc. This, coupled with the $add_dashes option,
    // makes it much easier for users to manually type or speak their passwords.
    //
    // Note: the $add_dashes option will increase the length of the password by
    // floor(sqrt(N)) characters.

    private function generateStrongPassword($length = 9, $add_dashes = false, $available_sets = 'luds')
    {
        $sets = array();
        if (strpos($available_sets, 'l') !== false) {
            $sets[] = 'abcdefghjkmnpqrstuvwxyz';
        }
        if (strpos($available_sets, 'u') !== false) {
            $sets[] = 'ABCDEFGHJKMNPQRSTUVWXYZ';
        }
        if (strpos($available_sets, 'd') !== false) {
            $sets[] = '23456789';
        }
        if (strpos($available_sets, 's') !== false) {
            $sets[] = '!@#$%&*?';
        }

        $all = '';
        $password = '';
        foreach ($sets as $set) {
            $password .= $set[array_rand(str_split($set))];
            $all .= $set;
        }

        $all = str_split($all);
        for ($i = 0; $i < $length - count($sets); $i++) {
            $password .= $all[array_rand($all)];
        }

        $password = str_shuffle($password);

        if (!$add_dashes) {
            return $password;
        }

        $dash_len = floor(sqrt($length));
        $dash_str = '';
        while (strlen($password) > $dash_len) {
            $dash_str .= substr($password, 0, $dash_len) . '-';
            $password = substr($password, $dash_len);
        }
        $dash_str .= $password;
        return $dash_str;
    }
}
