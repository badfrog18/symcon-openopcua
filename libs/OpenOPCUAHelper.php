<?php

declare(strict_types=1);

require_once __DIR__ . '/autoload.php';

use PhpOpcua\Client\Client;
use PhpOpcua\Client\ClientBuilder;
use PhpOpcua\Client\Security\SecurityMode;
use PhpOpcua\Client\Security\SecurityPolicy;
use PhpOpcua\Client\Types\AttributeId;
use PhpOpcua\Client\Types\BuiltinType;
use PhpOpcua\Client\Types\DataValue;
use PhpOpcua\Client\Types\NodeClass;
use PhpOpcua\Client\Types\NodeId;
use PhpOpcua\Client\Types\SessionState;
use PhpOpcua\Client\Types\StatusCode;

/**
 * IPS-unabhängige Hilfsfunktionen (dadurch auch außerhalb von Symcon testbar).
 */
final class OpenOPCUAHelper
{
    // IPS-Variablentypen
    public const IPS_BOOL = 0;
    public const IPS_INT = 1;
    public const IPS_FLOAT = 2;
    public const IPS_STRING = 3;

    /** Unterstützte Builtin-Typen → Anzeigename */
    public const TYPE_NAMES = [
        1  => 'Boolean', 2 => 'SByte', 3 => 'Byte', 4 => 'Int16', 5 => 'UInt16', 6 => 'Int32',
        7  => 'UInt32', 8 => 'Int64', 9 => 'UInt64', 10 => 'Float', 11 => 'Double', 12 => 'String',
        13 => 'DateTime', 14 => 'Guid', 15 => 'ByteString', 17 => 'NodeId', 19 => 'StatusCode',
        20 => 'QualifiedName', 21 => 'LocalizedText',
    ];

    /** Wertebereiche für Ganzzahl-Schreibzugriffe */
    private const INT_RANGES = [
        2 => [-128, 127], 3 => [0, 255], 4 => [-32768, 32767], 5 => [0, 65535],
        6 => [-2147483648, 2147483647], 7 => [0, 4294967295], 8 => [PHP_INT_MIN, PHP_INT_MAX], 9 => [0, PHP_INT_MAX],
    ];

    public static function policyFromName(string $name): SecurityPolicy
    {
        foreach (SecurityPolicy::cases() as $case) {
            if ($case->name === $name) {
                return $case;
            }
        }
        return SecurityPolicy::None;
    }

    public static function modeFromName(string $name): SecurityMode
    {
        foreach (SecurityMode::cases() as $case) {
            if ($case->name === $name) {
                return $case;
            }
        }
        return SecurityMode::None;
    }

    /**
     * Baut eine Verbindung auf. $config: Endpoint, SecurityPolicy, SecurityMode, AuthMode,
     * Username, Password, Timeout (s), SessionTimeout (ms), CertFile, KeyFile, Session (?array)
     */
    public static function connect(array $config): Client
    {
        $policy = self::policyFromName((string) ($config['SecurityPolicy'] ?? 'None'));
        $mode = self::modeFromName((string) ($config['SecurityMode'] ?? 'None'));
        if ($policy === SecurityPolicy::None) {
            $mode = SecurityMode::None;
        } elseif ($mode === SecurityMode::None) {
            $mode = SecurityMode::SignAndEncrypt;
        }

        $builder = ClientBuilder::create()
            ->setTimeout(max(1.0, (float) ($config['Timeout'] ?? 5)))
            ->setSessionTimeout((float) ($config['SessionTimeout'] ?? 60000))
            ->setAutoRetry(0)
            ->setCache(null)
            ->setSecurityPolicy($policy)
            ->setSecurityMode($mode);

        if ($policy !== SecurityPolicy::None && !empty($config['CertFile']) && !empty($config['KeyFile'])) {
            $builder->setClientCertificate($config['CertFile'], $config['KeyFile']);
        }
        if (($config['AuthMode'] ?? 'Anonymous') === 'UserPassword' && ($config['Username'] ?? '') !== '') {
            $builder->setUserCredentials((string) $config['Username'], (string) ($config['Password'] ?? ''));
        }
        if (!empty($config['Session']) && is_array($config['Session'])) {
            try {
                $builder->resumeSession(SessionState::fromArray($config['Session']));
            } catch (\Throwable) {
                // kaputter Session-Cache → neue Session
            }
        }
        return $builder->connect((string) $config['Endpoint']);
    }

    /** Beendet die Verbindung; bei $keepSession wird die Session für den nächsten Zyklus geparkt. */
    public static function close(?Client $client, bool $keepSession): ?array
    {
        if ($client === null) {
            return null;
        }
        try {
            if ($keepSession) {
                $state = $client->suspend();
                return $state?->jsonSerialize();
            }
            $client->disconnect();
        } catch (\Throwable) {
        }
        return null;
    }

    /**
     * Durchsucht den Adressraum rekursiv und liefert alle Variablen.
     * @return array<int, array{NodeId:string, Path:string, Name:string, BuiltinType:int, ValueRank:int, Writable:bool, Supported:bool, Hint:string, Value:string}>
     */
    public static function browse(Client $client, string $root, int $maxDepth, int $maxNodes = 3000): array
    {
        $found = [];
        $visited = [];
        $queue = [[$root, '', 0]];
        $classes = [NodeClass::Object, NodeClass::Variable];

        while ($queue && count($found) < $maxNodes) {
            [$nodeId, $path, $depth] = array_shift($queue);
            if (isset($visited[$nodeId])) {
                continue;
            }
            $visited[$nodeId] = true;
            try {
                $refs = $client->browseAll($nodeId, nodeClasses: $classes, useCache: false);
            } catch (\Throwable) {
                continue;
            }
            foreach ($refs as $ref) {
                if (!$ref->isForward) {
                    continue;
                }
                $id = $ref->nodeId->toString();
                // Standard-Namespace (Server-Objekt, Diagnose …) ausblenden
                if ($ref->nodeId->namespaceIndex === 0) {
                    continue;
                }
                $name = (string) ($ref->displayName->text ?? '') ?: $ref->browseName->name;
                $childPath = $path === '' ? $name : $path . '/' . $name;
                if ($ref->nodeClass === NodeClass::Variable && !isset($found[$id])) {
                    $found[$id] = ['NodeId' => $id, 'Path' => $childPath, 'Name' => $name];
                }
                if ($depth + 1 < $maxDepth) {
                    $queue[] = [$id, $childPath, $depth + 1];
                }
            }
        }

        if (!$found) {
            return [];
        }

        // Metadaten nachlesen: DataType, ValueRank, AccessLevel, Value
        $items = [];
        foreach ($found as $id => $_) {
            foreach ([AttributeId::DataType, AttributeId::ValueRank, AttributeId::AccessLevel, AttributeId::Value] as $attr) {
                $items[] = ['nodeId' => $id, 'attributeId' => $attr];
            }
        }
        $results = [];
        foreach (array_chunk($items, 400) as $chunk) {
            try {
                foreach ($client->readMulti($chunk) as $dv) {
                    $results[] = $dv;
                }
            } catch (\PhpOpcua\Client\Exception\ConnectionException $e) {
                throw $e;
            } catch (\Throwable) {
                // Ein nicht dekodierbarer Wert darf nicht den ganzen Block kippen → einzeln lesen
                foreach ($chunk as $item) {
                    try {
                        $results[] = $client->read($item['nodeId'], $item['attributeId']);
                    } catch (\PhpOpcua\Client\Exception\ConnectionException $e) {
                        throw $e;
                    } catch (\Throwable) {
                        $results[] = new DataValue(null, 0x80000000);
                    }
                }
            }
        }

        $out = [];
        $i = 0;
        foreach ($found as $id => $node) {
            /** @var DataValue $dtDv */
            $dtDv = $results[$i++];
            $rankDv = $results[$i++];
            $accDv = $results[$i++];
            $valDv = $results[$i++];

            $builtin = 0;
            $dt = $dtDv->getValue();
            if ($dt instanceof NodeId && $dt->namespaceIndex === 0 && is_int($dt->identifier) && isset(self::TYPE_NAMES[$dt->identifier])) {
                $builtin = $dt->identifier;
            }
            // Fallback (z. B. Enum/Subtypen): Typ des aktuellen Werts
            $valueType = $valDv->getType();
            if ($builtin === 0 && $valueType !== null && isset(self::TYPE_NAMES[$valueType->value])) {
                $builtin = $valueType->value;
            }
            $rank = (int) ($rankDv->getValue() ?? -1);
            $access = (int) ($accDv->getValue() ?? 1);
            $isArray = $rank >= 0 || is_array($valDv->getValue());

            $hint = '';
            $supported = true;
            if ($builtin === 0) {
                $supported = false;
                $hint = 'Struktur/unbekannter Typ – Elemente einzeln übernehmen';
            } elseif ($isArray) {
                $hint = 'Array → nur lesend als JSON-Text';
            }

            $out[] = $node + [
                'BuiltinType' => $builtin,
                'ValueRank'   => $isArray ? 1 : -1,
                'Writable'    => $supported && !$isArray && ($access & 0x02) === 0x02,
                'Readable'    => ($access & 0x01) === 0x01,
                'Supported'   => $supported,
                'Hint'        => $hint,
                'Value'       => $supported ? self::formatValue($valDv->getValue(), $builtin, $isArray) : '',
            ];
        }
        usort($out, static fn ($a, $b) => strnatcasecmp($a['Path'], $b['Path']));
        return $out;
    }

    /** Ziel-Variablentyp in IPS */
    public static function ipsType(int $builtin, bool $isArray): int
    {
        if ($isArray) {
            return self::IPS_STRING;
        }
        return match ($builtin) {
            1 => self::IPS_BOOL,
            2, 3, 4, 5, 6, 13 => self::IPS_INT,      // DateTime → Unix-Timestamp
            7, 8, 9, 10, 11 => self::IPS_FLOAT,      // UInt32/64-Bit passen nicht sicher in IPS-Integer
            default => self::IPS_STRING,
        };
    }

    /** OPC-UA-Wert → IPS-Wert */
    public static function toIps(mixed $value, int $builtin, bool $isArray): mixed
    {
        if ($isArray || is_array($value)) {
            return json_encode(self::plain($value), JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
        }
        if ($builtin === 15 && is_string($value)) {
            return bin2hex($value);
        }
        return match (self::ipsType($builtin, false)) {
            self::IPS_BOOL  => (bool) $value,
            self::IPS_INT   => $value instanceof \DateTimeInterface ? $value->getTimestamp() : (int) $value,
            self::IPS_FLOAT => (float) $value,
            default         => self::plainString($value),
        };
    }

    /** Wert für die Anzeige in Übersicht/Kachel */
    public static function formatValue(mixed $value, int $builtin, bool $isArray): string
    {
        if ($value === null) {
            return '–';
        }
        if ($isArray || is_array($value)) {
            return (string) json_encode(self::plain($value), JSON_UNESCAPED_UNICODE);
        }
        if (is_bool($value)) {
            return $value ? 'TRUE' : 'FALSE';
        }
        if ($builtin === 15 && is_string($value)) {
            return strtoupper(bin2hex($value));
        }
        if ($value instanceof \DateTimeInterface) {
            return $value->setTimezone(new \DateTimeZone(date_default_timezone_get()))->format('d.m.Y H:i:s');
        }
        if (is_float($value)) {
            $s = rtrim(rtrim(number_format($value, 4, ',', '.'), '0'), ',');
            return $s === '-0' ? '0' : $s;
        }
        return self::plainString($value);
    }

    /** IPS-/Eingabewert → typisierter OPC-UA-Wert. Wirft bei ungültiger Eingabe. */
    public static function toOpcUa(mixed $value, int $builtin): mixed
    {
        switch ($builtin) {
            case 1:
                if (is_string($value)) {
                    return in_array(strtolower(trim($value)), ['1', 'true', 'ein', 'on', 'yes', 'ja'], true);
                }
                return (bool) $value;
            case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9:
                if (is_string($value)) {
                    $value = trim($value);
                    if (!preg_match('/^-?\d+$/', $value)) {
                        throw new \InvalidArgumentException("'$value' ist keine Ganzzahl");
                    }
                }
                $int = (int) round((float) $value);
                [$min, $max] = self::INT_RANGES[$builtin];
                if ($int < $min || $int > $max) {
                    throw new \InvalidArgumentException(sprintf('%d liegt außerhalb %s (%d … %d)', $int, self::TYPE_NAMES[$builtin], $min, $max));
                }
                return $int;
            case 10: case 11:
                if (is_string($value)) {
                    $value = str_replace(',', '.', trim($value));
                    if (!is_numeric($value)) {
                        throw new \InvalidArgumentException("'$value' ist keine Zahl");
                    }
                }
                return (float) $value;
            case 12:
                return (string) $value;
        }
        throw new \InvalidArgumentException('Schreiben für Typ ' . (self::TYPE_NAMES[$builtin] ?? $builtin) . ' nicht unterstützt');
    }

    public static function builtin(int $builtin): BuiltinType
    {
        return BuiltinType::from($builtin);
    }

    public static function statusName(int $code): string
    {
        return $code === 0 ? 'Good' : StatusCode::getName($code);
    }

    public static function isGood(int $code): bool
    {
        return ($code & 0xC0000000) === 0;
    }

    public static function isBad(int $code): bool
    {
        return ($code & 0x80000000) !== 0;
    }

    /** Stabiler, IPS-tauglicher Ident aus der NodeId */
    public static function ident(string $nodeId): string
    {
        return 'N' . substr(md5($nodeId), 0, 16);
    }

    /** Erzeugt ein selbstsigniertes RSA-Client-Zertifikat (PEM). */
    public static function createCertificate(string $applicationUri, string $commonName): array
    {
        $host = gethostname() ?: 'localhost';
        $cfg = "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN={$commonName}\nO=Symcon\n"
            . "[v3]\nbasicConstraints=critical,CA:FALSE\n"
            . "keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment\n"
            . "extendedKeyUsage=clientAuth,serverAuth\nsubjectKeyIdentifier=hash\n"
            . "subjectAltName=URI:{$applicationUri},DNS:{$host}\n";
        $tmp = tempnam(sys_get_temp_dir(), 'oopcua');
        file_put_contents($tmp, $cfg);
        try {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'config' => $tmp]);
            if ($key === false) {
                throw new \RuntimeException('Schlüssel konnte nicht erzeugt werden: ' . openssl_error_string());
            }
            $csr = openssl_csr_new(['CN' => $commonName, 'O' => 'Symcon'], $key, ['digest_alg' => 'sha256', 'config' => $tmp]);
            $cert = openssl_csr_sign($csr, null, $key, 3650, ['digest_alg' => 'sha256', 'config' => $tmp, 'x509_extensions' => 'v3'], random_int(1, PHP_INT_MAX));
            if ($cert === false) {
                throw new \RuntimeException('Zertifikat konnte nicht signiert werden: ' . openssl_error_string());
            }
            openssl_x509_export($cert, $certPem);
            openssl_pkey_export($key, $keyPem, null, ['config' => $tmp]);
            return ['cert' => $certPem, 'key' => $keyPem];
        } finally {
            @unlink($tmp);
        }
    }

    public static function pemToDer(string $pem): string
    {
        $b64 = preg_replace('/-----[^-]+-----|\s+/', '', $pem);
        return (string) base64_decode((string) $b64);
    }

    private static function plain(mixed $value): mixed
    {
        if (is_array($value)) {
            return array_map([self::class, 'plain'], $value);
        }
        if (is_scalar($value) || $value === null) {
            return $value;
        }
        return self::plainString($value);
    }

    private static function plainString(mixed $value): string
    {
        if ($value === null) {
            return '';
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_scalar($value)) {
            return (string) $value;
        }
        if ($value instanceof \DateTimeInterface) {
            return $value->format(DATE_ATOM);
        }
        if (is_object($value) && property_exists($value, 'text')) {
            return (string) $value->text;          // LocalizedText
        }
        if (is_object($value) && method_exists($value, '__toString')) {
            return (string) $value;
        }
        return (string) json_encode($value);
    }
}
