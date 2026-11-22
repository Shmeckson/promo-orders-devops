<?php
// Безпечні параметри cookie сесії
$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

// Генерація CSRF-токена, якщо його ще немає в сесії
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf_token'];

// Ключ шифрування конфіденційних даних (для навчального прикладу; у продакшені — у змінних середовища)
define('ENC_KEY', hash('sha256', 'promo_crm_variant12_secret_key_2026', true));

function encryptSecret(?string $plainText): string {
    if ($plainText === null || $plainText === '') {
        return '';
    }
    $ivLen = openssl_cipher_iv_length('AES-256-CBC');
    $iv = random_bytes($ivLen);
    $encrypted = openssl_encrypt($plainText, 'AES-256-CBC', ENC_KEY, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encrypted);
}

function decryptSecret(?string $cipherBase64): string {
    if ($cipherBase64 === null || $cipherBase64 === '') {
        return '';
    }
    $raw = base64_decode($cipherBase64, true);
    if ($raw === false) {
        return '[Помилка декодування]';
    }
    $ivLen = openssl_cipher_iv_length('AES-256-CBC');
    if (strlen($raw) <= $ivLen) {
        return htmlspecialchars($cipherBase64, ENT_QUOTES, 'UTF-8');
    }
    $iv = substr($raw, 0, $ivLen);
    $cipherText = substr($raw, $ivLen);
    $decrypted = openssl_decrypt($cipherText, 'AES-256-CBC', ENC_KEY, OPENSSL_RAW_DATA, $iv);
    return $decrypted !== false ? $decrypted : '[Не вдалося розшифрувати]';
}

function h(?string $value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// Підключення до MySQL
$host = 'localhost';
$user = 'root';
$pass = '';
$dbname = 'promo_crm_db';

$mysqli = new mysqli($host, $user, $pass, $dbname);
if ($mysqli->connect_error) {
    die('Помилка підключення до бази даних: ' . h($mysqli->connect_error));
}
$mysqli->set_charset('utf8mb4');

$message = '';
$error = '';
$allowedStatuses = ['Нове', 'В роботі', 'Нанесення лого', 'Готово'];

// Перевірка CSRF для всіх POST-запитів
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!is_string($submittedToken) || !hash_equals($_SESSION['csrf_token'], $submittedToken)) {
        http_response_code(403);
        die('Помилка безпеки CSRF: недійсний токен запиту.');
    }
}

// Створення замовлення (параметризований запит + шифрування конфіденційного поля)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'create') {
    $client_name = trim($_POST['client_name'] ?? '');
    $crm_lead_id = trim($_POST['crm_lead_id'] ?? '');
    $item_type   = trim($_POST['item_type'] ?? '');
    $quantity    = (int)($_POST['quantity'] ?? 0);
    $status      = trim($_POST['status'] ?? 'Нове');
    $crm_synced  = isset($_POST['crm_synced']) ? 1 : 0;
    $secret_note = trim($_POST['secret_note'] ?? '');

    if (!in_array($status, $allowedStatuses, true)) {
        $status = 'Нове';
    }

    if ($client_name === '' || $crm_lead_id === '' || $item_type === '' || $quantity <= 0) {
        $error = 'Заповніть усі обов’язкові поля та вкажіть кількість більше 0.';
    } else {
        $encryptedNote = encryptSecret($secret_note);
        $stmt = $mysqli->prepare(
            "INSERT INTO promo_orders (client_name, crm_lead_id, item_type, quantity, status, crm_synced, secret_note)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        );
        $stmt->bind_param('sssisis', $client_name, $crm_lead_id, $item_type, $quantity, $status, $crm_synced, $encryptedNote);
        if ($stmt->execute()) {
            $message = 'Замовлення безпечно додано до бази даних!';
        } else {
            $error = 'Помилка збереження: ' . h($stmt->error);
        }
        $stmt->close();
    }
}

// Оновлення статусу та синхронізації з CRM (параметризований запит)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'update_status') {
    $id         = (int)($_POST['id'] ?? 0);
    $status     = trim($_POST['status'] ?? 'Нове');
    $crm_synced = ((int)($_POST['crm_synced'] ?? 0) === 1) ? 1 : 0;

    if (!in_array($status, $allowedStatuses, true)) {
        $status = 'Нове';
    }

    if ($id > 0) {
        $stmt = $mysqli->prepare("UPDATE promo_orders SET status = ?, crm_synced = ? WHERE id = ?");
        $stmt->bind_param('sii', $status, $crm_synced, $id);
        if ($stmt->execute()) {
            $message = "Замовлення #$id оновлено.";
        }
        $stmt->close();
    }
}

// Видалення через POST з CSRF-токеном (захист від CSRF-атак через посилання)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete') {
    $delete_id = (int)($_POST['id'] ?? 0);
    if ($delete_id > 0) {
        $stmt = $mysqli->prepare("DELETE FROM promo_orders WHERE id = ?");
        $stmt->bind_param('i', $delete_id);
        if ($stmt->execute()) {
            $message = "Замовлення #$delete_id видалено.";
        }
        $stmt->close();
    }
}

// Отримання записів
$orders = [];
$result = $mysqli->query("SELECT * FROM promo_orders ORDER BY id DESC");
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $orders[] = $row;
    }
    $result->free();
}
$mysqli->close();
?>
<!DOCTYPE html>
<html lang="uk">
<head>
    <meta charset="UTF-8">
    <title>ЛР7 — Безпека веб-застосунку (Варіант 12)</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1080px;
            margin: 28px auto;
            padding: 0 16px;
            background: #f1f5f9;
            color: #0f172a;
        }
        .sec-bar {
            background: #0f172a;
            color: #e2e8f0;
            padding: 12px 18px;
            border-radius: 8px;
            margin-bottom: 18px;
            font-size: 14px;
        }
        .card {
            background: #ffffff;
            padding: 20px 24px;
            border-radius: 10px;
            margin-bottom: 22px;
            box-shadow: 0 2px 8px rgba(15, 23, 42, 0.06);
        }
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 14px;
        }
        label {
            display: flex;
            flex-direction: column;
            gap: 6px;
            font-weight: bold;
            font-size: 14px;
        }
        input, select {
            padding: 8px 10px;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            font-size: 14px;
        }
        .checkbox-row {
            flex-direction: row;
            align-items: center;
            margin-top: 22px;
        }
        .checkbox-row input {
            width: auto;
        }
        button {
            padding: 8px 14px;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            font-size: 14px;
        }
        .btn-primary {
            background: #0284c7;
            color: #fff;
            margin-top: 16px;
        }
        .btn-save {
            background: #0f766e;
            color: #fff;
        }
        .btn-del {
            background: #dc2626;
            color: #fff;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 14px;
        }
        th, td {
            border-bottom: 1px solid #e2e8f0;
            padding: 10px 8px;
            text-align: left;
            vertical-align: top;
        }
        .msg {
            padding: 10px 14px;
            border-radius: 6px;
            margin-bottom: 16px;
            font-weight: bold;
        }
        .ok { background: #dcfce7; color: #166534; }
        .err { background: #fee2e2; color: #991b1b; }
        .badge-ok { color: #15803d; font-weight: bold; }
        .badge-no { color: #b45309; font-weight: bold; }
        .cipher-box {
            font-size: 12px;
            color: #64748b;
            word-break: break-all;
            margin-top: 4px;
        }
    </style>
</head>
<body>
    <h1>Захист веб-застосунку: промо-одяг та інтеграція з CRM (ЛР7, Варіант 12)</h1>

    <div class="sec-bar">
        <strong>Активні механізми захисту:</strong>
        XSS (htmlspecialchars) • CSRF (токени + POST) • SQL Injection (prepared statements) • Шифрування (AES-256-CBC) • З’єднання: <strong><?= $isHttps ? 'HTTPS (захищене)' : 'HTTP (локальний режим; увімкніть SSL/TLS для HTTPS)' ?></strong>
    </div>

    <?php if ($message !== ''): ?>
        <div class="msg ok"><?= h($message) ?></div>
    <?php endif; ?>
    <?php if ($error !== ''): ?>
        <div class="msg err"><?= h($error) ?></div>
    <?php endif; ?>

    <div class="card">
        <h2>Нове замовлення промо-одягу</h2>
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
            <input type="hidden" name="action" value="create">
            <div class="form-grid">
                <label>
                    Клієнт / Компанія:
                    <input type="text" name="client_name" required placeholder="Напр., ТОВ «Альфа»">
                </label>
                <label>
                    ID ліда / угоди в CRM:
                    <input type="text" name="crm_lead_id" required placeholder="Напр., CRM-2001">
                </label>
                <label>
                    Вид промо-одягу:
                    <input type="text" name="item_type" required placeholder="Футболки, худі, кепки...">
                </label>
                <label>
                    Наклад (шт.):
                    <input type="number" name="quantity" min="1" required value="50">
                </label>
                <label>
                    Статус замовлення:
                    <select name="status">
                        <?php foreach ($allowedStatuses as $st): ?>
                            <option value="<?= h($st) ?>"><?= h($st) ?></option>
                        <?php endforeach; ?>
                    </select>
                </label>
                <label>
                    Конфіденційна примітка (шифрується):
                    <input type="text" name="secret_note" placeholder="Умови оплати / дані CRM">
                </label>
                <label class="checkbox-row">
                    <input type="checkbox" name="crm_synced" value="1" checked>
                    Синхронізовано з CRM
                </label>
            </div>
            <button type="submit" class="btn-primary">Додати замовлення</button>
        </form>
    </div>

    <div class="card">
        <h2>Список замовлень у базі даних</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Клієнт</th>
                    <th>CRM ID</th>
                    <th>Виріб</th>
                    <th>К-сть</th>
                    <th>Конфіденційні дані</th>
                    <th>CRM-статус</th>
                    <th>Оновлення</th>
                    <th>Видалення</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($orders as $order): ?>
                    <tr>
                        <td><?= (int)$order['id'] ?></td>
                        <td><?= h($order['client_name']) ?></td>
                        <td><?= h($order['crm_lead_id']) ?></td>
                        <td><?= h($order['item_type']) ?></td>
                        <td><?= (int)$order['quantity'] ?></td>
                        <td>
                            <div><strong>Розшифровано:</strong> <?= h(decryptSecret($order['secret_note'] ?? '')) ?></div>
                            <div class="cipher-box">У БД (AES-256): <?= h($order['secret_note'] ?? '') ?></div>
                        </td>
                        <td>
                            <?php if ((int)$order['crm_synced'] === 1): ?>
                                <span class="badge-ok">Синхронізовано</span>
                            <?php else: ?>
                                <span class="badge-no">Очікує CRM</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <form method="POST" action="" style="display:flex; gap:6px; align-items:center;">
                                <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                                <input type="hidden" name="action" value="update_status">
                                <input type="hidden" name="id" value="<?= (int)$order['id'] ?>">
                                <select name="status">
                                    <?php foreach ($allowedStatuses as $st): ?>
                                        <option value="<?= h($st) ?>" <?= $order['status'] === $st ? 'selected' : '' ?>>
                                            <?= h($st) ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <select name="crm_synced">
                                    <option value="1" <?= (int)$order['crm_synced'] === 1 ? 'selected' : '' ?>>CRM: Так</option>
                                    <option value="0" <?= (int)$order['crm_synced'] === 0 ? 'selected' : '' ?>>CRM: Ні</option>
                                </select>
                                <button type="submit" class="btn-save">OK</button>
                            </form>
                        </td>
                        <td>
                            <form method="POST" action="" onsubmit="return confirm('Видалити замовлення?');">
                                <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="id" value="<?= (int)$order['id'] ?>">
                                <button type="submit" class="btn-del">Видалити</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</body>
</html>