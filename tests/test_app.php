<?php

function validateOrderInput(string $clientName, string $crmLeadId, string $itemType, int $quantity, string $status): array {
    $allowedStatuses = ['Нове', 'В роботі', 'Нанесення лого', 'Готово'];
    $errors = [];

    if (trim($clientName) === '') {
        $errors[] = 'Client name is required';
    }
    if (trim($crmLeadId) === '') {
        $errors[] = 'CRM lead ID is required';
    }
    if (trim($itemType) === '') {
        $errors[] = 'Item type is required';
    }
    if ($quantity <= 0) {
        $errors[] = 'Quantity must be greater than 0';
    }
    if (!in_array($status, $allowedStatuses, true)) {
        $errors[] = 'Invalid status';
    }

    return $errors;
}

function assertTrue(bool $condition, string $message): void {
    if (!$condition) {
        fwrite(STDERR, "FAIL: $message\n");
        exit(1);
    }
    echo "PASS: $message\n";
}

$res1 = validateOrderInput('ТОВ «Альфа»', 'CRM-2001', 'Футболки', 100, 'В роботі');
assertTrue(count($res1) === 0, 'Valid promo order passes validation');

$res2 = validateOrderInput('ТОВ «Альфа»', 'CRM-2001', 'Худі', 0, 'Нове');
assertTrue(in_array('Quantity must be greater than 0', $res2, true), 'Zero quantity is rejected');

$res3 = validateOrderInput('ТОВ «Альфа»', 'CRM-2001', 'Кепки', 25, 'Невідомий');
assertTrue(in_array('Invalid status', $res3, true), 'Invalid order status is rejected');

echo "All tests passed successfully!\n";