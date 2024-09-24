<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');

$dsn = 'mysql:host=localhost;dbname=usersDB;charset=utf8';
$username = 'root';
$password = '';

try {
    $db = new PDO($dsn, $username, $password);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

$requestMethod = $_SERVER['REQUEST_METHOD'];
$path = explode('/', trim($_SERVER['PATH_INFO'], '/'));

switch ($requestMethod) {
    case 'POST':
        if ($path[0] === 'users') {
            createUser($db);
        } elseif ($path[0] === 'login') {
            loginUser($db);
        }
        break;

    case 'PUT':
        if ($path[0] === 'users' && isset($path[1])) {
            updateUser($db, $path[1]);
        }
        break;

    case 'DELETE':
        if ($path[0] === 'users' && isset($path[1])) {
            deleteUser($db, $path[1]);
        }
        break;

    case 'GET':
        if ($path[0] === 'users') {
            if (isset($path[1])) {
                getUser($db, $path[1]);
            } else {
                getAllUsers($db);
            }
        }
        break;

    default:
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function createUser($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($data['username']) || !isset($data['password'])) {
        echo json_encode(['error' => 'Username and password are required']);
        return;
    }

    try {
        $stmt = $db->prepare("INSERT INTO users (username, password, info) VALUES (?, ?, ?)");
        $passwordHash = password_hash($data['password'], PASSWORD_BCRYPT);
        $info = isset($data['info']) ? $data['info'] : null;

        if ($stmt->execute([$data['username'], $passwordHash, $info])) {
            echo json_encode(['message' => 'User created', 'id' => $db->lastInsertId()]);
        } else {
            echo json_encode(['error' => 'Failed to create user']);
        }
    } catch (PDOException $e) {
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

function updateUser($db, $id) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $fields = [];
    $params = [];

    if (isset($data['username'])) {
        $fields[] = "username = ?";
        $params[] = $data['username'];
    }
    if (isset($data['password'])) {
        $fields[] = "password = ?";
        $params[] = password_hash($data['password'], PASSWORD_BCRYPT);
    }
    if (isset($data['info'])) {
        $fields[] = "info = ?";
        $params[] = $data['info'];
    }

    if (empty($fields)) {
        echo json_encode(['error' => 'No fields to update']);
        return;
    }

    $params[] = $id;
    $stmt = $db->prepare("UPDATE users SET " . implode(', ', $fields) . " WHERE id = ?");
    
    if ($stmt->execute($params)) {
        echo json_encode(['message' => 'User updated']);
    } else {
        echo json_encode(['error' => 'Failed to update user']);
    }
}

function deleteUser($db, $id) {
    $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
    
    if ($stmt->execute([$id])) {
        echo json_encode(['message' => 'User deleted']);
    } else {
        echo json_encode(['error' => 'Failed to delete user']);
    }
}

function loginUser($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($data['username']) || !isset($data['password'])) {
        echo json_encode(['error' => 'Username and password are required']);
        return;
    }

    $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$data['username']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($data['password'], $user['password'])) {
        echo json_encode(['message' => 'Login successful', 'user' => ['id' => $user['id'], 'username' => $user['username'], 'info' => $user['info']]]);
    } else {
        echo json_encode(['error' => 'Invalid credentials']);
    }
}

function getUser($db, $id) {
    $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user) {
        echo json_encode($user);
    } else {
        echo json_encode(['error' => 'User not found']);
    }
}

function getAllUsers($db) {
    $stmt = $db->query("SELECT id, username, info FROM users");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo json_encode($users);
}
?>