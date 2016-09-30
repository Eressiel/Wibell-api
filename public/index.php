<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;

require '../vendor/autoload.php';


$config['displayErrorDetails'] = true;
$config['addContentLengthHeader'] = false;

require '../classes/dbconfig.php';

//$app = new \Slim\App;
$app = new \Slim\App(["settings" => $config]);

$container = $app->getContainer();

$container['logger'] = function($c) {
    $logger = new \Monolog\Logger('my_logger');
    $file_handler = new \Monolog\Handler\StreamHandler("../logs/app.log");
    $logger->pushHandler($file_handler);
    return $logger;
};

$container['db'] = function ($c) {
    $db = $c['settings']['db'];
    $pdo = new PDO("mysql:host=" . $db['host'] . ";dbname=" . $db['dbname'],
        $db['user'], $db['pass']);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    return $pdo;
};

$app->get('/neco', function (Request $request, Response $response, $args) {
    //$body = $request->getParsedBody();
    
    $db = $this->db;
    $dataAry = array(
        "login_token" => "toto je token",
        "message" => "logged in successfully",
        "data" => $body
    );
    
    $response->withHeader('Content-Type', 'application/json');
    $response->withStatus(200);
    $response->withJson($dataAry);
    
    return $response;
});

$app->post('/v1/newwibell', function (Request $request, Response $response, $args) {
    $db = $this->db;
    if(!isJsonContentType($request->getContentType())){
        return $response->withStatus(400, "Wrong content Type");
    }
    
    $body = $request->getParsedBody();
    if (!isset($body['name'])){
        $body['name'] = "WiBell";
    }
    
    $stmt = $db->prepare("INSERT INTO wibell (ID, name, user_ID) VALUES (?, ?, ?)");
    $stmt->bindParam("ssi",$body['id'], $body['name'], $body['user_id']);

    $data = array($body['id'], $body['name'], $body['user_id']);
    $stmt->execute($data);
    
    $this->logger->log(100, "[WIBELL REGISTRATION] WiBell ".$body['id']." has been added to the DB.");
    return $response;
});

$app->post('/v1/user/signup', function (Request $request, Response $response, $args) {
    $db = $this->db;
    if(!isJsonContentType($request->getContentType())){
        return $response->withStatus(400, "Wrong content Type");
    }
    
    $body = $request->getParsedBody();
    
    if(!isset($body['email']) || !isset($body['password'])){
        return $response->withStatus(400, "Email and passworn need to be provided.");
    }
    
    if (userAlreadyExists($this, $body['email'])){
        return $response->withStatus(400, "User already exists.");
    }
    $body['salt'] = substr(RandomToken(), 0, 10);
    
    $stmt = $db->prepare("INSERT INTO user (email, password, salt, last_login_attempt, name) VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)");
    $stmt->bindParam("ssss",$body['email'], $body['password'], $body['salt'], $body['name']);
    
    $data = array($body['email'], $body['password'], $body['salt'], $body['name']);
    
    if(!$stmt->execute($data)){
        $this->logger->error("[USER REGISTRATION] Error registering user ".$body['email']);
        return $response->withStatus(400, "Server error.");
    }
    
    $this->logger->log(100,"[USER REGISTRATION] User ".$body['email']." successfully registered.");
    $response->withStatus(200);
});

$app->post('/v1/user/login', function (Request $request, Response $response, $args) {
    $db = $this->db;
    
    $this->logger->debug("Login Attempt");
    $body = $request->getParsedBody();
    
    $query = 'SELECT ID, email, password, login_token, attempts_left, last_login_attempt, stay_logged
            FROM user
            WHERE email = :email 
            LIMIT 1';
    
    $sql = $db->prepare($query);
    $sql->bindValue(":email", $body['email']);
    $sql->execute();
    
    if($sql->rowCount() == 0){
        // No such user like that
        $dataArray = array(
            "message" => "Given credentials are incorrect"
        );

        $response->withHeader('Content-Type', 'application/json');
        $response->withStatus(400);
        $response->withJson($dataArray);
    }
    
    $user = $sql->fetch(\PDO::FETCH_ASSOC);
    
    foreach ($user as $key => $value) {
        $this->logger->debug("[user login]".$key.":".$value);
    }
    

    if ($user['attempts_left'] <= 0){
        $diffInMinutes = round(abs($user['last_login_attempt'] - time()) / 60, 0);
        if ($diffInMinutes > 5){ 
            //reset attempts
            $updatedUserInfo['attempts_left'] = 5;
        } else{
            $response->withStatus(400, "Account temporarily blocked, please try again later.");
        }
    } else{
        $diffInMinutes = round(abs($user['last_login_attempt'] - time()) / 60, 0);
        if ($diffInMinutes > 5){
            //reset attempts
            $updatedUserInfo['attempts_left'] = 5;
        }

    }
    
    if(verifyPassword($body['password'], $user['password'])){
        $updatedUserInfo['last_login_attempt'] = 'CURRENT_TIMESTAMP';
        $updatedUserInfo['attempts_left'] = 5;
        $updatedUserInfo['login_token'] = RandomToken();
        $verified = TRUE;
        if (isset($body['stay_logged']) && $body['stay_logged']){
            $updatedUserInfo['stay_logged'] = TRUE;
        } else {
            $updatedUserInfo['stay_logged'] = FALSE;
        }
    } else{
        $updatedUserInfo['attempts_left'] = ($user['attempts_left'] + 0) - 1;
        $verified = FALSE;
        
        $updatedUserInfo['stay_logged'] = FALSE;
        $updatedUserInfo['last_login_attempt'] = 'CURRENT_TIMESTAMP';
        $updatedUserInfo['login_token'] = NULL;
        
    }
    
    foreach ($updatedUserInfo as $key => $value) {
        $user[$key] = $value;
    }
    
    try {
        $stmt = $db->prepare("UPDATE user "
                . "SET login_token = ?, attempts_left = ?, "
                . "    last_login_attempt = CURRENT_TIMESTAMP, stay_logged = ?"
                . "WHERE ID = ?");
        $stmt->bindParam("siii",$user['login_token'], $user['attempts_left'], 
                $user['stay_logged'], $user['ID']);
        $data = array($user['login_token'], $user['attempts_left'], 
                $user['stay_logged'], $user['ID']);
        $stmt->execute($data);
        
        
        
        if ($verified){
            
            if (!deviceWithFirebaseTokenExists($db, $body['firebasetoken'], $user['ID'])){
                addDeviceToUser($db, $body['firebasetoken'], $body['devicename'], $user['ID']);
            }
                        
            $message = "Login successful";
            $response->withStatus(200);
        } else{
            $message = "Login failed";
            $response->withStatus(400);
        }
        $dataArray = array(
            "login_token" => $user['login_token'],
            "message" => $message
        );
        $response->withHeader('Content-Type', 'application/json');
        $response->withJson($dataArray);
    } catch (PDOException $e){
        $this->logger->error("[USER LOGIN] ".$e->getMessage());
        return $response->withStatus(400, "User login failed. Please, try again later.");
    }
});

function deviceWithFirebaseTokenExists($db, $firebaseToken, $userID){
    $query = 'SELECT ID, firebase_token, name
            FROM device
            WHERE firebase_token = :firebaseToken AND user_ID = :user_ID
            LIMIT 1';
    
    $stmt = $db->prepare($query);
    $stmt->bindValue(":firebaseToken", $firebaseToken);
    $stmt->bindValue(":user_ID", $userID);
    $stmt->execute();
    
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if(isset($row['ID']) && $row['ID'] > 0){
        return $row;
    }else {
        return false;
    }
}

function addDeviceToUser($db, $firebaseToken, $name, $user_ID){
    
    $data = array($firebaseToken, $name, $user_ID);
    
    $stmt = $db->prepare("INSERT INTO device (firebase_token, name, user_ID) VALUES (?, ?, ?)");
    $stmt->bindParam("ssi", $firebaseToken, $name, $user_ID);
    return $stmt->execute($data);
}

function verifyPassword($password, $storedPassword){
    if (!is_string($password) || strlen($password) != strlen($storedPassword) || strlen($password) <= 3) { //TODO ZMENIT 3 NA 13 !!!!!!!!!!!!
        return false;                         // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    }
    
    $status = 0;
    for ($i = 0; $i < strlen($password); $i++) {
        $status |= (ord($password[$i]) ^ ord($storedPassword[$i]));
    }
    
    return $status === 0;
}

function userAlreadyExists($app, $email){
    $db = $app->db;
    
    $query = 'SELECT email
            FROM user
            WHERE email = :email
            LIMIT 1';
    
    $stmt = $db->prepare($query);
    $stmt->bindValue(":email", $email);
    $stmt->execute();
    
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    foreach ($row as $key => $value) {
        $app->logger->debug("[user exist?]  ".$key.":".$value);
    }
    return strlen($row['email']) > 0 ? true : false;
}

function isJsonContentType($cntType){
    return $cntType === "application/json" ? true : false;
}

function RandomToken($length = 32){
    if(!isset($length) || intval($length) <= 8 ){
      $length = 32;
    }
    if (function_exists('random_bytes')) {
        return bin2hex(random_bytes($length));
    }
    if (function_exists('mcrypt_create_iv')) {
        return bin2hex(mcrypt_create_iv($length, MCRYPT_DEV_URANDOM));
    } 
    if (function_exists('openssl_random_pseudo_bytes')) {
        return bin2hex(openssl_random_pseudo_bytes($length));
    }
}

$app->post('/v1/device', function (Request $request, Response $response, $args) {
    $db = $this->db;
    $body = $request->getParsedBody();
    
    if (!isset($body['user_ID'])){
        return $response->withStatus(400, "User ID needs to be provided.");
    }
    
    $data = array($body['firebase_token'], $body['name'], $body['user_ID']);
    
    try{
        $stmt = $db->prepare("INSERT INTO device (firebase_token, name, user_ID) VALUES (?, ?, ?)");
        $stmt->bindParam("sss", $body['firebase_Token'], $body['name'], $body['user_ID']);
        $stmt->execute($data);
        $response->withStatus(200);
    } catch (Exception $e) {
        $this->logger->error("[DEVICE ADD] ".$e->getMessage());
        return $response->withStatus(400, "Error adding device.");
    }
});

$app->post('/v1/devicetoring', function (Request $request, Response $response, $args) {
    $db = $this->db;
    $body = $request->getParsedBody();
    if (!isset($body['firebasetoken']) || !isset($body['wibell_ID'])){
        return $response->withStatus(400, "Bad request.");
    }
    if (!isset($body['message'])){
        $body['message'] = "WiBell ringing!";
    }
    
    $deviceID = getDeviceIDFromFirebaseToken($db, $this->logger, $body['firebasetoken']);
    $dataArray = array(
        "status" => "activated",
    );
    $data = array($deviceID, $body['wibell_ID'], $body['message']);
    try{
        $stmt = $db->prepare("INSERT INTO devicetoring (device_ID, wibell_ID, message) VALUES (?, ?, ?)");
        $stmt->bindParam("iss", $deviceID, $body['wibell_ID'], $body['message']);
        $stmt->execute($data);
        $response->withStatus(200);
        $response->withJson($dataArray);
    } catch (Exception $e) {
        $this->logger->error("[DEVICE ADD] ".$e->getMessage());
        $response->withJson($dataArray);
        return $response->withStatus(200, "Error adding device.");
    }
    
});

$app->get('/v1/devicetoring/{token}', function (Request $request, Response $response, $args){
    $token = $args['token'];
    $db = $this->db;
    $logger = $this->logger;
    $device_ID = getDeviceIDFromFirebaseToken($db, $logger, $token);
    
    $query = 'SELECT Wibell_ID
            FROM devicetoring
            WHERE Device_ID = :Device_ID
            ';
    
    $stmt = $db->prepare($query);
    $stmt->bindValue(":token", $token);
    $stmt->execute();
    
    $rows = $stmt->fetch(PDO::FETCH_ASSOC);
    
    $response->withStatus(200);
    $response->withJson($rows);
    
});

function getDeviceIDFromFirebaseToken($db, $logger, $firebaseToken){
    try {
        $query = 'SELECT ID
            FROM device
            WHERE firebase_token = :firebaseToken';
    
        $stmt = $db->prepare($query);
        $stmt->bindValue(":firebaseToken", $firebaseToken);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        $logger->error("[GET DEVICE ID] ".$e->getMessage());
    }
    return $row['ID'];
}

function isWibellActive($db, $wibellID){
    // TODO 
}

$app->get('/v1/ring/firebase/{wibell_ID}', function (Request $request, Response $response, $args) {
    $db = $this->db;
    
    class DeviceNotificationInfo {
        public $firebase_token;
        public $wibell_ID;
        public $active;
        public $device_ID;
        public $name;
    }
    
    try{
        $stmt = $db->prepare("
            SELECT dtr.wibell_ID, dtr.device_ID, d.firebase_token, d.name, w.active
            FROM devicetoring dtr JOIN device d JOIN wibell w
            WHERE dtr.device_ID = d.ID AND dtr.wibell_ID = w.ID AND dtr.wibell_ID = :wibell_ID  
            ");
        $stmt->bindValue(":wibell_ID", $args['wibell_ID']);
        $stmt->execute();
        
        $devices = $stmt->fetchAll(PDO::FETCH_CLASS, "DeviceNotificationInfo");
        
    } catch (Exception $e) {
        $response->withStatus(400, "Error adding device.");
        $this->logger->error("[DEVICE ADD] ".$e->getMessage());
        $devices = NULL;
    }
    
    if (!$devices){
        $this->logger->info("[RING REQUEST] Ringing request processed, but no devices assigned to ring.");
        return $response->withStatus(200);
    }
    
    foreach ($devices as $device) {
        if($device->active){
            $result = notifyDevice($device->firebase_token);
        }
    }
});
    
   
function notifyDevice($firebaseToken){
    define( 'API_ACCESS_KEY', 'AIzaSyDM-7C2aYnfNf3323qGjJFBGlReZ7gejUM' );
    
    // prep the bundle
    $msg = array
    (
            'message' 	=> 'here is a message. message',
            'title'		=> 'This is a title. title',
            'subtitle'	=> 'This is a subtitle. subtitle',
            'tickerText'	=> 'Ticker text here...Ticker text here'
            
    );
    $fields = array
    (
            'to' 	=> $firebaseToken,
            'notification' => array(
                'body'  => 'Message body',
                'title' => 'great message!'
            ),
            'data'			=> $msg
    );

    $headers = array
    (
            'Authorization: key=' . API_ACCESS_KEY,
            'Content-Type: application/json'
    );

    $ch = curl_init();
    curl_setopt( $ch,CURLOPT_URL, 'https://android.googleapis.com/gcm/send' );
    curl_setopt( $ch,CURLOPT_POST, true );
    curl_setopt( $ch,CURLOPT_HTTPHEADER, $headers );
    curl_setopt( $ch,CURLOPT_RETURNTRANSFER, true );
    curl_setopt( $ch,CURLOPT_SSL_VERIFYPEER, false );
    curl_setopt( $ch,CURLOPT_POSTFIELDS, json_encode( $fields ) );
    $result = curl_exec($ch );
    curl_close( $ch );
    return $result;
}


$app->run();