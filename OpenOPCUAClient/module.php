<?php

declare(strict_types=1);

require_once __DIR__ . '/../libs/OpenOPCUAHelper.php';

/**
 * OpenOPCUA Client – freier OPC-UA-Client für IP-Symcon.
 * Gedacht für SIMATIC S7-1200 (G2) / S7-1500, funktioniert mit jedem OPC-UA-Server.
 */
class OpenOPCUAClient extends IPSModule
{
    private const STATUS_ACTIVE = 102;
    private const STATUS_INACTIVE = 104;
    private const STATUS_CONNECT_FAILED = 201;
    private const STATUS_NO_NODES = 202;
    private const STATUS_CERT_ERROR = 203;

    public function Create(): void
    {
        parent::Create();

        $this->RegisterPropertyBoolean('Active', true);
        $this->RegisterPropertyString('Endpoint', 'opc.tcp://192.168.178.10:4840');
        $this->RegisterPropertyString('SecurityPolicy', 'None');
        $this->RegisterPropertyString('SecurityMode', 'SignAndEncrypt');
        $this->RegisterPropertyString('AuthMode', 'Anonymous');
        $this->RegisterPropertyString('Username', '');
        $this->RegisterPropertyString('Password', '');
        $this->RegisterPropertyInteger('Interval', 1000);
        $this->RegisterPropertyInteger('Timeout', 5);
        $this->RegisterPropertyBoolean('KeepSession', true);
        $this->RegisterPropertyString('BrowseRoot', 'i=85');
        $this->RegisterPropertyInteger('BrowseDepth', 10);
        $this->RegisterPropertyString('Nodes', '[]');

        $this->RegisterAttributeString('CertPem', '');
        $this->RegisterAttributeString('KeyPem', '');
        $this->RegisterAttributeString('BrowseResult', '[]');

        $this->RegisterTimer('Update', 0, 'OOPCUA_Update($_IPS[\'TARGET\']);');

        // Kachel-Visualisierung (HTML-SDK)
        $this->SetVisualizationType(1);
    }

    public function Destroy(): void
    {
        foreach ([$this->certFile(), $this->keyFile(), $this->downloadFile()] as $f) {
            if (is_file($f)) {
                @unlink($f);
            }
        }
        parent::Destroy();
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();

        $this->SetBuffer('Session', '');
        $this->SetBuffer('LastError', '');

        // Variablen pflegen
        $nodes = $this->getNodes();
        $keep = [];
        $pos = 0;
        foreach ($nodes as $n) {
            $ident = OpenOPCUAHelper::ident($n['NodeId']);
            $keep[$ident] = true;
            $type = OpenOPCUAHelper::ipsType((int) $n['BuiltinType'], (bool) $n['Array']);
            $profile = match (true) {
                $type === OpenOPCUAHelper::IPS_BOOL => '~Switch',
                (int) $n['BuiltinType'] === 13 && !$n['Array'] => '~UnixTimestamp',
                default => '',
            };
            $this->MaintainVariable($ident, $n['Name'] !== '' ? $n['Name'] : $n['NodeId'], $type, $profile, ++$pos * 10, true);
            if ($n['Writable'] && !$n['Array']) {
                $this->EnableAction($ident);
            } else {
                $this->DisableAction($ident);
            }
        }
        // Variablen entfernter Nodes löschen (nur eigene, am Ident erkennbar)
        foreach (IPS_GetChildrenIDs($this->InstanceID) as $child) {
            $obj = IPS_GetObject($child);
            if ($obj['ObjectType'] === 2 && preg_match('/^N[0-9a-f]{16}$/', $obj['ObjectIdent']) && !isset($keep[$obj['ObjectIdent']])) {
                $this->UnregisterVariable($obj['ObjectIdent']);
            }
        }

        // Zertifikat bereitstellen, falls Security aktiv
        if ($this->ReadPropertyString('SecurityPolicy') !== 'None') {
            try {
                $this->ensureCertificate();
            } catch (\Throwable $e) {
                $this->SetStatus(self::STATUS_CERT_ERROR);
                $this->SetTimerInterval('Update', 0);
                return;
            }
        }

        if (!$this->ReadPropertyBoolean('Active') || trim($this->ReadPropertyString('Endpoint')) === '') {
            $this->SetStatus(self::STATUS_INACTIVE);
            $this->SetTimerInterval('Update', 0);
        } elseif (!$this->activeNodes()) {
            $this->SetStatus(self::STATUS_NO_NODES);
            $this->SetTimerInterval('Update', 0);
        } else {
            $this->SetStatus(self::STATUS_ACTIVE);
            $this->SetTimerInterval('Update', max(100, $this->ReadPropertyInteger('Interval')));
        }

        $this->SetSummary($this->ReadPropertyString('Endpoint'));
        $this->pushVisualization();
    }

    // ------------------------------------------------------------------
    // Öffentliche Funktionen (OOPCUA_*)
    // ------------------------------------------------------------------

    /** Liest alle aktiven Nodes und aktualisiert die Variablen. */
    public function Update(): bool
    {
        $nodes = $this->activeNodes();
        if (!$nodes) {
            return false;
        }
        $start = microtime(true);
        $ok = $this->withClient(function ($client) use ($nodes) {
            $items = [];
            foreach ($nodes as $n) {
                $items[] = ['nodeId' => $n['NodeId']];
            }
            $results = [];
            foreach (array_chunk($items, 200) as $chunk) {
                foreach ($client->readMulti($chunk) as $dv) {
                    $results[] = $dv;
                }
            }
            $live = $this->getLive();
            $now = time();
            foreach (array_values($nodes) as $i => $n) {
                $dv = $results[$i] ?? null;
                if ($dv === null) {
                    continue;
                }
                $ident = OpenOPCUAHelper::ident($n['NodeId']);
                $status = $dv->statusCode;
                $entry = $live[$ident] ?? ['v' => null, 'f' => '–'];
                $entry['s'] = $status;
                if (!OpenOPCUAHelper::isBad($status)) {
                    $value = $dv->getValue();
                    $ipsValue = OpenOPCUAHelper::toIps($value, (int) $n['BuiltinType'], (bool) $n['Array']);
                    $id = @$this->GetIDForIdent($ident);
                    if ($id !== false && $id > 0 && GetValue($id) !== $ipsValue) {
                        $this->SetValue($ident, $ipsValue);
                    }
                    $entry['v'] = is_scalar($ipsValue) ? $ipsValue : null;
                    $entry['f'] = OpenOPCUAHelper::formatValue($value, (int) $n['BuiltinType'], (bool) $n['Array']);
                    $entry['t'] = $dv->sourceTimestamp?->getTimestamp() ?? $now;
                }
                $live[$ident] = $entry;
            }
            $this->SetBuffer('Live', json_encode($live));
            return true;
        }, 'Lesen');

        $this->SetBuffer('CycleMs', (string) round((microtime(true) - $start) * 1000));
        $this->SetBuffer('LastUpdate', (string) time());
        $this->pushVisualization();
        $this->UpdateFormField('LiveList', 'values', json_encode($this->liveRows()));
        $this->UpdateFormField('LiveInfo', 'caption', $this->liveInfo());
        return $ok === true;
    }

    /** Liest eine beliebige NodeId (auch nicht importierte). */
    public function ReadNode(string $NodeId)
    {
        return $this->withClient(function ($client) use ($NodeId) {
            $dv = $client->read($NodeId);
            if (OpenOPCUAHelper::isBad($dv->statusCode)) {
                throw new \RuntimeException(OpenOPCUAHelper::statusName($dv->statusCode));
            }
            $v = $dv->getValue();
            return OpenOPCUAHelper::toIps($v, $dv->getType()?->value ?? 12, is_array($v));
        }, 'Lesen ' . $NodeId, true, false);
    }

    /** Schreibt eine beliebige NodeId; der Datentyp wird automatisch ermittelt. */
    public function WriteNode(string $NodeId, $Value): bool
    {
        $node = $this->findNode($NodeId);
        if ($node !== null) {
            return $this->writeNodeInternal($node, $Value);
        }
        return $this->withClient(function ($client) use ($NodeId, $Value) {
            $status = $client->write($NodeId, $Value);
            if (!OpenOPCUAHelper::isGood($status)) {
                throw new \RuntimeException(OpenOPCUAHelper::statusName($status));
            }
            return true;
        }, 'Schreiben ' . $NodeId, true, false) === true;
    }

    /** Durchsucht den Server und legt das Ergebnis für die Auswahlliste ab. */
    public function Browse(): int
    {
        $result = $this->withClient(function ($client) {
            return OpenOPCUAHelper::browse(
                $client,
                trim($this->ReadPropertyString('BrowseRoot')) ?: 'i=85',
                max(1, $this->ReadPropertyInteger('BrowseDepth'))
            );
        }, 'Durchsuchen', true, false);
        if (!is_array($result)) {
            return -1;
        }
        $this->WriteAttributeString('BrowseResult', json_encode($result, JSON_UNESCAPED_UNICODE));
        return count($result);
    }

    /** Übernimmt NodeIds aus dem Browse-Ergebnis (JSON-Array von NodeId-Strings). */
    public function ImportNodes(string $NodeIds): int
    {
        $ids = json_decode($NodeIds, true);
        if (!is_array($ids) || !$ids) {
            return 0;
        }
        $browse = [];
        foreach (json_decode($this->ReadAttributeString('BrowseResult'), true) ?: [] as $b) {
            $browse[$b['NodeId']] = $b;
        }
        $nodes = $this->getNodes();
        $existing = array_column($nodes, 'NodeId');
        $added = 0;
        foreach ($ids as $id) {
            if (in_array($id, $existing, true) || !isset($browse[$id]) || !$browse[$id]['Supported']) {
                continue;
            }
            $b = $browse[$id];
            $nodes[] = $this->nodeRow($b['NodeId'], $b['Name'], $b['Path'], (int) $b['BuiltinType'], $b['ValueRank'] >= 0, (bool) $b['Writable']);
            $added++;
        }
        if ($added > 0) {
            $this->saveNodes($nodes);
        }
        return $added;
    }

    /** Fügt eine NodeId manuell hinzu (Datentyp wird vom Server gelesen). */
    public function AddNode(string $NodeId, string $Name): bool
    {
        $NodeId = trim($NodeId);
        if ($NodeId === '' || $this->findNode($NodeId) !== null) {
            return false;
        }
        $info = $this->withClient(function ($client) use ($NodeId) {
            $cls = $client->read($NodeId, 2)->getValue();
            if ((int) $cls !== 2) {
                throw new \RuntimeException($cls === null ? 'NodeId nicht gefunden' : 'Node ist keine Variable (Objekt/Struktur?) – bitte die Elemente einzeln hinzufügen');
            }
            $res = $client->readMulti()
                ->node($NodeId)->dataType()
                ->node($NodeId)->attribute(15)
                ->node($NodeId)->attribute(17)
                ->node($NodeId)->value()
                ->node($NodeId)->displayName()
                ->execute();
            if (OpenOPCUAHelper::isBad($res[3]->statusCode) && OpenOPCUAHelper::isBad($res[0]->statusCode)) {
                throw new \RuntimeException('NodeId nicht gefunden: ' . OpenOPCUAHelper::statusName($res[3]->statusCode));
            }
            $dt = $res[0]->getValue();
            $builtin = ($dt instanceof \PhpOpcua\Client\Types\NodeId && $dt->namespaceIndex === 0 && is_int($dt->identifier)
                && isset(OpenOPCUAHelper::TYPE_NAMES[$dt->identifier])) ? $dt->identifier : ($res[3]->getType()?->value ?? 0);
            if (!isset(OpenOPCUAHelper::TYPE_NAMES[$builtin])) {
                throw new \RuntimeException('Datentyp wird nicht unterstützt (Struktur?)');
            }
            $display = $res[4]->getValue();
            return [
                'builtin'  => $builtin,
                'array'    => (int) ($res[1]->getValue() ?? -1) >= 0 || is_array($res[3]->getValue()),
                'writable' => (((int) ($res[2]->getValue() ?? 1)) & 0x02) === 0x02,
                'name'     => is_object($display) && property_exists($display, 'text') ? (string) $display->text : $NodeId,
            ];
        }, 'Hinzufügen ' . $NodeId, true, false);
        if (!is_array($info)) {
            return false;
        }
        $nodes = $this->getNodes();
        $nodes[] = $this->nodeRow($NodeId, $Name !== '' ? $Name : $info['name'], '', $info['builtin'], $info['array'], $info['writable'] && !$info['array']);
        $this->saveNodes($nodes);
        return true;
    }

    /** Erzeugt ein neues Client-Zertifikat (muss danach in der SPS erneut vertraut werden). */
    public function RenewCertificate(): bool
    {
        $this->WriteAttributeString('CertPem', '');
        $this->WriteAttributeString('KeyPem', '');
        $this->ensureCertificate();
        $this->SetBuffer('Session', '');
        return true;
    }

    // ------------------------------------------------------------------
    // Aktionen (Variablen, Kachel, Konfigurationsformular)
    // ------------------------------------------------------------------

    public function RequestAction($Ident, $Value): void
    {
        switch ($Ident) {
            case 'TestConnection':
                $info = $this->withClient(function ($client) {
                    $bi = null;
                    try {
                        $bi = $client->getServerBuildInfo();
                    } catch (\Throwable) {
                    }
                    return $bi ? trim(($bi->manufacturerName ?? '') . ' ' . ($bi->productName ?? '') . ' ' . ($bi->softwareVersion ?? '')) : 'OPC-UA-Server';
                }, 'Verbindungstest', true, false);
                if (is_string($info)) {
                    echo "✅ Verbindung erfolgreich\n\n" . $info;
                }
                return;

            case 'Browse':
                $this->UpdateFormField('BrowseProgress', 'visible', true);
                $count = $this->Browse();
                $this->UpdateFormField('BrowseProgress', 'visible', false);
                if ($count >= 0) {
                    $this->SetBuffer('BrowseFilter', '');
                    $this->UpdateFormField('BrowseFilter', 'value', '');
                    $this->UpdateFormField('BrowseList', 'values', json_encode($this->browseRows('', false)));
                    $this->UpdateFormField('BrowseInfo', 'caption', $this->browseInfo());
                    $this->UpdateFormField('BrowsePanel', 'expanded', true);
                }
                return;

            case 'FilterBrowse':
                $this->SetBuffer('BrowseFilter', (string) $Value);
                $this->UpdateFormField('BrowseList', 'values', json_encode($this->browseRows((string) $Value, false)));
                return;

            case 'SelectAllBrowse':
                $this->UpdateFormField('BrowseList', 'values', json_encode($this->browseRows($this->GetBuffer('BrowseFilter'), true)));
                return;

            case 'ImportSelection':
                $added = $this->ImportNodes((string) $Value);
                echo $added > 0 ? "✅ {$added} Variable(n) übernommen" : 'Keine neuen Variablen ausgewählt';
                return;

            case 'AddManual':
                $data = json_decode((string) $Value, true) ?: [];
                if ($this->AddNode((string) ($data['NodeId'] ?? ''), (string) ($data['Name'] ?? ''))) {
                    echo '✅ Variable hinzugefügt';
                }
                return;

            case 'ReadNow':
                if ($this->Update()) {
                    echo '✅ Werte gelesen (' . $this->GetBuffer('CycleMs') . ' ms)';
                }
                return;

            case 'RenewCertificate':
                $this->RenewCertificate();
                $this->ReloadForm();
                echo "Neues Zertifikat erzeugt – bitte in der SPS erneut als vertrauenswürdig hinterlegen.";
                return;
        }

        // Schreiben auf eine Node-Variable
        foreach ($this->getNodes() as $n) {
            if (OpenOPCUAHelper::ident($n['NodeId']) === $Ident) {
                if (!$n['Writable']) {
                    echo 'Variable ist nur lesbar';
                    return;
                }
                $this->writeNodeInternal($n, $Value);
                return;
            }
        }
        throw new \Exception('Unbekannter Ident: ' . $Ident);
    }

    // ------------------------------------------------------------------
    // Kachel
    // ------------------------------------------------------------------

    public function GetVisualizationTile(): string
    {
        $html = file_get_contents(__DIR__ . '/module.html');
        return $html . '<script>handleMessage(' . json_encode($this->visualizationPayload()) . ');</script>';
    }

    // ------------------------------------------------------------------
    // Konfigurationsformular
    // ------------------------------------------------------------------

    public function GetConfigurationForm(): string
    {
        $certInfo = 'Kein Zertifikat (Security "None")';
        if ($this->ReadAttributeString('CertPem') !== '') {
            $der = OpenOPCUAHelper::pemToDer($this->ReadAttributeString('CertPem'));
            $fp = strtoupper(implode(':', str_split(sha1($der), 2)));
            $certInfo = "Client-Zertifikat (SHA1): {$fp}\nDownload: http://<IPS-IP>:3777/user/" . basename($this->downloadFile());
        }

        $policyOptions = [];
        foreach (['None', 'Basic256Sha256', 'Aes128Sha256RsaOaep', 'Aes256Sha256RsaPss', 'Basic256', 'Basic128Rsa15'] as $p) {
            $policyOptions[] = ['caption' => $p, 'value' => $p];
        }

        $form = [
            'elements' => [
                ['type' => 'CheckBox', 'name' => 'Active', 'caption' => 'Aktiv'],
                [
                    'type'     => 'ExpansionPanel',
                    'caption'  => 'Verbindung',
                    'expanded' => true,
                    'items'    => [
                        ['type' => 'ValidationTextBox', 'name' => 'Endpoint', 'caption' => 'Endpoint (opc.tcp://IP:4840)', 'width' => '420px',
                            'validate' => '^opc\.tcp://.+'],
                        ['type' => 'RowLayout', 'items' => [
                            ['type' => 'Select', 'name' => 'SecurityPolicy', 'caption' => 'Security Policy', 'options' => $policyOptions],
                            ['type' => 'Select', 'name' => 'SecurityMode', 'caption' => 'Security Mode', 'options' => [
                                ['caption' => 'Sign', 'value' => 'Sign'],
                                ['caption' => 'Sign & Encrypt', 'value' => 'SignAndEncrypt'],
                            ]],
                        ]],
                        ['type' => 'RowLayout', 'items' => [
                            ['type' => 'Select', 'name' => 'AuthMode', 'caption' => 'Anmeldung', 'options' => [
                                ['caption' => 'Anonym (Gast)', 'value' => 'Anonymous'],
                                ['caption' => 'Benutzer / Passwort', 'value' => 'UserPassword'],
                            ]],
                            ['type' => 'ValidationTextBox', 'name' => 'Username', 'caption' => 'Benutzer'],
                            ['type' => 'PasswordTextBox', 'name' => 'Password', 'caption' => 'Passwort'],
                        ]],
                        ['type' => 'RowLayout', 'items' => [
                            ['type' => 'NumberSpinner', 'name' => 'Interval', 'caption' => 'Abfrageintervall', 'suffix' => 'ms', 'minimum' => 100],
                            ['type' => 'NumberSpinner', 'name' => 'Timeout', 'caption' => 'Timeout', 'suffix' => 's', 'minimum' => 1, 'maximum' => 60],
                            ['type' => 'CheckBox', 'name' => 'KeepSession', 'caption' => 'Session zwischen Zyklen weiterverwenden (schneller)'],
                        ]],
                        ['type' => 'Label', 'caption' => $certInfo],
                    ],
                ],
                [
                    'type'    => 'ExpansionPanel',
                    'caption' => 'Durchsuchen (Erweitert)',
                    'items'   => [
                        ['type' => 'ValidationTextBox', 'name' => 'BrowseRoot', 'caption' => 'Start-Node (Standard i=85 = Objects)'],
                        ['type' => 'NumberSpinner', 'name' => 'BrowseDepth', 'caption' => 'Max. Tiefe', 'minimum' => 1, 'maximum' => 30],
                    ],
                ],
                [
                    'type'     => 'List',
                    'name'     => 'Nodes',
                    'caption'  => 'Übernommene Variablen',
                    'rowCount' => 12,
                    'add'      => false,
                    'delete'   => true,
                    'sort'     => ['column' => 'Path', 'direction' => 'ascending'],
                    'columns'  => [
                        ['caption' => 'Aktiv', 'name' => 'Active', 'width' => '60px', 'add' => true, 'edit' => ['type' => 'CheckBox']],
                        ['caption' => 'Name', 'name' => 'Name', 'width' => '220px', 'add' => '', 'edit' => ['type' => 'ValidationTextBox']],
                        ['caption' => 'Pfad', 'name' => 'Path', 'width' => 'auto', 'add' => ''],
                        ['caption' => 'NodeId', 'name' => 'NodeId', 'width' => '300px', 'add' => ''],
                        ['caption' => 'Typ', 'name' => 'Type', 'width' => '100px', 'add' => ''],
                        ['caption' => 'Schreiben', 'name' => 'Writable', 'width' => '90px', 'add' => false, 'edit' => ['type' => 'CheckBox']],
                        ['caption' => 'BuiltinType', 'name' => 'BuiltinType', 'add' => 0, 'visible' => false],
                        ['caption' => 'Array', 'name' => 'Array', 'add' => false, 'visible' => false],
                    ],
                ],
            ],
            'actions' => [
                ['type' => 'RowLayout', 'items' => [
                    ['type' => 'Button', 'caption' => 'Verbindung testen', 'onClick' => 'IPS_RequestAction($id, "TestConnection", "");'],
                    ['type' => 'Button', 'caption' => 'Server durchsuchen', 'onClick' => 'IPS_RequestAction($id, "Browse", "");'],
                    ['type' => 'Button', 'caption' => 'Werte jetzt lesen', 'onClick' => 'IPS_RequestAction($id, "ReadNow", "");'],
                    ['type' => 'ProgressBar', 'name' => 'BrowseProgress', 'indeterminate' => true, 'visible' => false, 'caption' => 'Durchsuche …', 'width' => '200px'],
                ]],
                [
                    'type'     => 'ExpansionPanel',
                    'name'     => 'BrowsePanel',
                    'caption'  => 'Variablen vom Server auswählen',
                    'expanded' => false,
                    'items'    => [
                        ['type' => 'Label', 'name' => 'BrowseInfo', 'caption' => $this->browseInfo()],
                        ['type' => 'RowLayout', 'items' => [
                            ['type' => 'ValidationTextBox', 'name' => 'BrowseFilter', 'caption' => 'Filter (Pfad/NodeId)', 'width' => '300px',
                                'onChange' => 'IPS_RequestAction($id, "FilterBrowse", $BrowseFilter);'],
                            ['type' => 'Button', 'caption' => 'Alle sichtbaren markieren', 'onClick' => 'IPS_RequestAction($id, "SelectAllBrowse", "");'],
                            ['type' => 'Button', 'caption' => '➕ Markierte übernehmen',
                                'onClick' => '$s = []; foreach ($BrowseList as $r) { if ($r["Import"]) { $s[] = $r["NodeId"]; } } IPS_RequestAction($id, "ImportSelection", json_encode($s));'],
                        ]],
                        [
                            'type'     => 'List',
                            'name'     => 'BrowseList',
                            'rowCount' => 15,
                            'add'      => false,
                            'delete'   => false,
                            'sort'     => ['column' => 'Path', 'direction' => 'ascending'],
                            'columns'  => [
                                ['caption' => '✓', 'name' => 'Import', 'width' => '50px', 'edit' => ['type' => 'CheckBox']],
                                ['caption' => 'Pfad', 'name' => 'Path', 'width' => 'auto'],
                                ['caption' => 'NodeId', 'name' => 'NodeId', 'width' => '300px'],
                                ['caption' => 'Typ', 'name' => 'Type', 'width' => '100px'],
                                ['caption' => 'Zugriff', 'name' => 'Access', 'width' => '70px'],
                                ['caption' => 'Wert', 'name' => 'Value', 'width' => '120px'],
                                ['caption' => 'Hinweis', 'name' => 'Hint', 'width' => '260px'],
                            ],
                            'values' => $this->browseRows($this->GetBuffer('BrowseFilter'), false),
                        ],
                        ['type' => 'RowLayout', 'items' => [
                            ['type' => 'ValidationTextBox', 'name' => 'ManualNodeId', 'caption' => 'NodeId manuell (z. B. ns=3;s="DB_IPS"."Wert")', 'width' => '380px'],
                            ['type' => 'ValidationTextBox', 'name' => 'ManualName', 'caption' => 'Name (optional)'],
                            ['type' => 'Button', 'caption' => 'Hinzufügen',
                                'onClick' => 'IPS_RequestAction($id, "AddManual", json_encode(["NodeId" => $ManualNodeId, "Name" => $ManualName]));'],
                        ]],
                    ],
                ],
                [
                    'type'     => 'ExpansionPanel',
                    'caption'  => 'Live-Übersicht',
                    'expanded' => true,
                    'items'    => [
                        ['type' => 'Label', 'name' => 'LiveInfo', 'caption' => $this->liveInfo()],
                        [
                            'type'     => 'List',
                            'name'     => 'LiveList',
                            'rowCount' => 15,
                            'add'      => false,
                            'delete'   => false,
                            'sort'     => ['column' => 'Group', 'direction' => 'ascending'],
                            'columns'  => [
                                ['caption' => 'Gruppe', 'name' => 'Group', 'width' => '220px'],
                                ['caption' => 'Name', 'name' => 'Name', 'width' => 'auto'],
                                ['caption' => 'Wert', 'name' => 'Value', 'width' => '160px'],
                                ['caption' => 'Typ', 'name' => 'Type', 'width' => '90px'],
                                ['caption' => 'R/W', 'name' => 'Access', 'width' => '60px'],
                                ['caption' => 'Status', 'name' => 'Status', 'width' => '160px'],
                                ['caption' => 'Zeitstempel', 'name' => 'Time', 'width' => '150px'],
                            ],
                            'values' => $this->liveRows(),
                        ],
                    ],
                ],
                [
                    'type'    => 'ExpansionPanel',
                    'caption' => 'Zertifikat',
                    'items'   => [
                        ['type' => 'Label', 'caption' => 'Nur bei Security Policy ≠ None nötig. Das Zertifikat muss in der SPS (TIA: Zertifikatsverwaltung / "Clientzertifikate zur Laufzeit automatisch akzeptieren") vertraut werden.'],
                        ['type' => 'Button', 'caption' => 'Neues Client-Zertifikat erzeugen',
                            'confirm' => 'Das bisherige Zertifikat wird ungültig. Fortfahren?',
                            'onClick' => 'IPS_RequestAction($id, "RenewCertificate", "");'],
                    ],
                ],
            ],
            'status' => [
                ['code' => self::STATUS_ACTIVE, 'icon' => 'active', 'caption' => 'Verbunden / aktiv'],
                ['code' => self::STATUS_INACTIVE, 'icon' => 'inactive', 'caption' => 'Instanz inaktiv'],
                ['code' => self::STATUS_CONNECT_FAILED, 'icon' => 'error', 'caption' => 'Verbindung zum OPC-UA-Server fehlgeschlagen'],
                ['code' => self::STATUS_NO_NODES, 'icon' => 'inactive', 'caption' => 'Keine Variablen ausgewählt – "Server durchsuchen" verwenden'],
                ['code' => self::STATUS_CERT_ERROR, 'icon' => 'error', 'caption' => 'Client-Zertifikat konnte nicht erzeugt werden'],
            ],
        ];
        return json_encode($form, JSON_UNESCAPED_UNICODE);
    }

    // ------------------------------------------------------------------
    // Intern
    // ------------------------------------------------------------------

    /**
     * Führt $fn mit verbundenem Client aus (Semaphore, Session-Wiederverwendung, Fehlerbehandlung).
     * @return mixed Rückgabe von $fn oder null bei Fehler
     */
    private function withClient(callable $fn, string $what, bool $echoError = false, bool $affectStatus = true): mixed
    {
        $sem = 'OOPCUA_' . $this->InstanceID;
        if (!IPS_SemaphoreEnter($sem, ($this->ReadPropertyInteger('Timeout') + 2) * 1000)) {
            $this->SendDebug($what, 'Übersprungen – vorherige Anfrage läuft noch', 0);
            return null;
        }
        $client = null;
        $keep = $this->ReadPropertyBoolean('KeepSession');
        try {
            $session = $keep ? json_decode($this->GetBuffer('Session'), true) : null;
            $client = OpenOPCUAHelper::connect($this->connectionConfig(is_array($session) ? $session : null));
            $result = $fn($client);
            $state = OpenOPCUAHelper::close($client, $keep);
            $client = null;
            $this->SetBuffer('Session', $state ? json_encode($state) : '');
            if ($affectStatus) {
                $this->setConnected(true);
            }
            return $result;
        } catch (\Throwable $e) {
            OpenOPCUAHelper::close($client, false);
            $this->SetBuffer('Session', '');
            $msg = $e->getMessage() ?: get_class($e);
            $this->SendDebug($what, 'Fehler: ' . $msg, 0);
            if ($affectStatus) {
                $this->setConnected(false, $msg);
            }
            if ($echoError) {
                echo "❌ {$what} fehlgeschlagen:\n{$msg}";
            }
            return null;
        } finally {
            IPS_SemaphoreLeave($sem);
        }
    }

    private function setConnected(bool $ok, string $error = ''): void
    {
        $prev = $this->GetBuffer('LastError');
        if ($ok) {
            if ($prev !== '') {
                $this->LogMessage('Verbindung wiederhergestellt', KL_MESSAGE);
            }
            $this->SetBuffer('LastError', '');
            if ($this->GetStatus() === self::STATUS_CONNECT_FAILED) {
                $this->SetStatus(self::STATUS_ACTIVE);
            }
        } else {
            if ($prev === '') {
                $this->LogMessage('Verbindung fehlgeschlagen: ' . $error, KL_ERROR);
            }
            $this->SetBuffer('LastError', $error ?: 'Fehler');
            if ($this->GetStatus() === self::STATUS_ACTIVE) {
                $this->SetStatus(self::STATUS_CONNECT_FAILED);
            }
        }
    }

    private function writeNodeInternal(array $n, mixed $value): bool
    {
        try {
            $typed = OpenOPCUAHelper::toOpcUa($value, (int) $n['BuiltinType']);
        } catch (\Throwable $e) {
            echo '❌ ' . $e->getMessage();
            return false;
        }
        $ok = $this->withClient(function ($client) use ($n, $typed) {
            $status = $client->write($n['NodeId'], $typed, OpenOPCUAHelper::builtin((int) $n['BuiltinType']));
            if (!OpenOPCUAHelper::isGood($status)) {
                throw new \RuntimeException('Server meldet ' . OpenOPCUAHelper::statusName($status));
            }
            return true;
        }, 'Schreiben ' . $n['Name'], true);

        if ($ok === true) {
            $ident = OpenOPCUAHelper::ident($n['NodeId']);
            $ipsValue = OpenOPCUAHelper::toIps($typed, (int) $n['BuiltinType'], false);
            $this->SetValue($ident, $ipsValue);
            $live = $this->getLive();
            $live[$ident] = ['v' => $ipsValue, 'f' => OpenOPCUAHelper::formatValue($typed, (int) $n['BuiltinType'], false), 's' => 0, 't' => time()];
            $this->SetBuffer('Live', json_encode($live));
            $this->pushVisualization();
            return true;
        }
        return false;
    }

    private function connectionConfig(?array $session = null): array
    {
        $secure = $this->ReadPropertyString('SecurityPolicy') !== 'None';
        if ($secure) {
            $this->ensureCertificate();
        }
        $interval = $this->ReadPropertyInteger('Interval');
        return [
            'Endpoint'       => trim($this->ReadPropertyString('Endpoint')),
            'SecurityPolicy' => $this->ReadPropertyString('SecurityPolicy'),
            'SecurityMode'   => $this->ReadPropertyString('SecurityMode'),
            'AuthMode'       => $this->ReadPropertyString('AuthMode'),
            'Username'       => $this->ReadPropertyString('Username'),
            'Password'       => $this->ReadPropertyString('Password'),
            'Timeout'        => $this->ReadPropertyInteger('Timeout'),
            'SessionTimeout' => (float) max(30000, $interval * 10),
            'CertFile'       => $secure ? $this->certFile() : '',
            'KeyFile'        => $secure ? $this->keyFile() : '',
            'Session'        => $session,
        ];
    }

    private function ensureCertificate(): void
    {
        if ($this->ReadAttributeString('CertPem') === '' || $this->ReadAttributeString('KeyPem') === '') {
            $pair = OpenOPCUAHelper::createCertificate('urn:symcon:openopcua:' . $this->InstanceID, 'Symcon OpenOPCUA ' . $this->InstanceID);
            $this->WriteAttributeString('CertPem', $pair['cert']);
            $this->WriteAttributeString('KeyPem', $pair['key']);
        }
        $dir = dirname($this->certFile());
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        $cert = $this->ReadAttributeString('CertPem');
        if (!is_file($this->certFile()) || !is_file($this->keyFile()) || file_get_contents($this->certFile()) !== $cert) {
            file_put_contents($this->certFile(), $cert);
            file_put_contents($this->keyFile(), $this->ReadAttributeString('KeyPem'));
            @chmod($this->keyFile(), 0600);
            $dl = $this->downloadFile();
            if (is_dir(dirname($dl))) {
                @file_put_contents($dl, OpenOPCUAHelper::pemToDer($cert));
            }
        }
    }

    private function certFile(): string
    {
        return IPS_GetKernelDir() . 'OpenOPCUA' . DIRECTORY_SEPARATOR . 'client_' . $this->InstanceID . '.pem';
    }

    private function keyFile(): string
    {
        return IPS_GetKernelDir() . 'OpenOPCUA' . DIRECTORY_SEPARATOR . 'client_' . $this->InstanceID . '.key';
    }

    private function downloadFile(): string
    {
        return IPS_GetKernelDir() . 'webfront' . DIRECTORY_SEPARATOR . 'user' . DIRECTORY_SEPARATOR . 'OpenOPCUA_' . $this->InstanceID . '.der';
    }

    /** @return array<int, array> normalisierte Node-Liste */
    private function getNodes(): array
    {
        $list = json_decode($this->ReadPropertyString('Nodes'), true);
        $out = [];
        foreach (is_array($list) ? $list : [] as $n) {
            if (empty($n['NodeId'])) {
                continue;
            }
            $out[] = [
                'Active'      => (bool) ($n['Active'] ?? true),
                'Name'        => (string) ($n['Name'] ?? ''),
                'Path'        => (string) ($n['Path'] ?? ''),
                'NodeId'      => (string) $n['NodeId'],
                'Type'        => (string) ($n['Type'] ?? ''),
                'Writable'    => (bool) ($n['Writable'] ?? false),
                'BuiltinType' => (int) ($n['BuiltinType'] ?? 12),
                'Array'       => (bool) ($n['Array'] ?? false),
            ];
        }
        return $out;
    }

    private function activeNodes(): array
    {
        return array_values(array_filter($this->getNodes(), static fn ($n) => $n['Active']));
    }

    private function findNode(string $nodeId): ?array
    {
        foreach ($this->getNodes() as $n) {
            if ($n['NodeId'] === $nodeId) {
                return $n;
            }
        }
        return null;
    }

    private function nodeRow(string $nodeId, string $name, string $path, int $builtin, bool $array, bool $writable): array
    {
        return [
            'Active'      => true,
            'Name'        => $name,
            'Path'        => $path,
            'NodeId'      => $nodeId,
            'Type'        => (OpenOPCUAHelper::TYPE_NAMES[$builtin] ?? '?') . ($array ? '[]' : ''),
            'Writable'    => $writable,
            'BuiltinType' => $builtin,
            'Array'       => $array,
        ];
    }

    private function saveNodes(array $nodes): void
    {
        IPS_SetProperty($this->InstanceID, 'Nodes', json_encode(array_values($nodes), JSON_UNESCAPED_UNICODE));
        IPS_ApplyChanges($this->InstanceID);
        $this->ReloadForm();
    }

    private function getLive(): array
    {
        $live = json_decode($this->GetBuffer('Live'), true);
        return is_array($live) ? $live : [];
    }

    private function groupOf(array $n): string
    {
        if ($n['Path'] === '') {
            return 'Manuell';
        }
        $parts = explode('/', $n['Path']);
        array_pop($parts);
        // "PLC_1/DataBlocksGlobal/" o. ä. weglassen → letzte zwei Ebenen reichen meist
        return implode(' / ', array_slice($parts, -2)) ?: '–';
    }

    private function liveRows(): array
    {
        $live = $this->getLive();
        $rows = [];
        foreach ($this->getNodes() as $n) {
            $l = $live[OpenOPCUAHelper::ident($n['NodeId'])] ?? null;
            $status = $l['s'] ?? null;
            $rows[] = [
                'Group'    => $this->groupOf($n),
                'Name'     => $n['Name'],
                'Value'    => $l['f'] ?? '–',
                'Type'     => $n['Type'],
                'Access'   => $n['Writable'] ? 'R/W' : 'R',
                'Status'   => !$n['Active'] ? 'inaktiv' : ($status === null ? 'noch nicht gelesen' : OpenOPCUAHelper::statusName((int) $status)),
                'Time'     => isset($l['t']) ? date('d.m.Y H:i:s', (int) $l['t']) : '',
                'rowColor' => !$n['Active'] ? '#EEEEEE' : ($status === null ? '' : (OpenOPCUAHelper::isBad((int) $status) ? '#FFC0C0' : (OpenOPCUAHelper::isGood((int) $status) ? '' : '#FFFFC0'))),
            ];
        }
        return $rows;
    }

    private function liveInfo(): string
    {
        $last = (int) $this->GetBuffer('LastUpdate');
        $err = $this->GetBuffer('LastError');
        $count = count($this->activeNodes());
        $txt = "{$count} aktive Variable(n)";
        if ($last > 0) {
            $txt .= ' · letzter Zyklus ' . date('H:i:s', $last) . ' (' . $this->GetBuffer('CycleMs') . ' ms)';
        }
        if ($err !== '') {
            $txt .= ' · ❌ ' . $err;
        }
        return $txt;
    }

    private function browseRows(string $filter, bool $selectAll): array
    {
        $existing = array_flip(array_column($this->getNodes(), 'NodeId'));
        $rows = [];
        $filter = mb_strtolower(trim($filter));
        foreach (json_decode($this->ReadAttributeString('BrowseResult'), true) ?: [] as $b) {
            if ($filter !== '' && !str_contains(mb_strtolower($b['Path'] . ' ' . $b['NodeId']), $filter)) {
                continue;
            }
            $imported = isset($existing[$b['NodeId']]);
            $rows[] = [
                'Import'   => $selectAll && $b['Supported'] && !$imported,
                'Path'     => $b['Path'],
                'NodeId'   => $b['NodeId'],
                'Type'     => (OpenOPCUAHelper::TYPE_NAMES[$b['BuiltinType']] ?? 'Struktur') . ($b['ValueRank'] >= 0 ? '[]' : ''),
                'Access'   => $b['Writable'] ? 'R/W' : 'R',
                'Value'    => mb_strimwidth((string) $b['Value'], 0, 40, '…'),
                'Hint'     => $imported ? 'bereits übernommen' : $b['Hint'],
                'rowColor' => $imported ? '#C8F0C8' : ($b['Supported'] ? '' : '#E8E8E8'),
            ];
        }
        return $rows;
    }

    private function browseInfo(): string
    {
        $all = json_decode($this->ReadAttributeString('BrowseResult'), true) ?: [];
        if (!$all) {
            return 'Noch nicht durchsucht – "Server durchsuchen" klicken.';
        }
        $sup = count(array_filter($all, static fn ($b) => $b['Supported']));
        return count($all) . " Variablen gefunden, davon {$sup} übernehmbar. Grün = bereits übernommen, grau = Struktur (Elemente einzeln wählen).";
    }

    private function visualizationPayload(): string
    {
        $live = $this->getLive();
        $rows = [];
        foreach ($this->getNodes() as $n) {
            if (!$n['Active']) {
                continue;
            }
            $ident = OpenOPCUAHelper::ident($n['NodeId']);
            $l = $live[$ident] ?? null;
            $status = isset($l['s']) ? (int) $l['s'] : null;
            $rows[] = [
                'i'  => $ident,
                'n'  => $n['Name'] ?: $n['NodeId'],
                'g'  => $this->groupOf($n),
                'id' => $n['NodeId'],
                'f'  => $l['f'] ?? '–',
                'v'  => $l['v'] ?? null,
                'ty' => $n['Type'],
                'b'  => $n['BuiltinType'],
                'w'  => $n['Writable'] && !$n['Array'],
                's'  => $status === null ? 'unknown' : (OpenOPCUAHelper::isBad($status) ? 'bad' : (OpenOPCUAHelper::isGood($status) ? 'good' : 'uncertain')),
                'sn' => $status === null ? 'noch nicht gelesen' : OpenOPCUAHelper::statusName($status),
                't'  => $l['t'] ?? null,
            ];
        }
        $err = $this->GetBuffer('LastError');
        return json_encode([
            'name'     => IPS_GetName($this->InstanceID),
            'endpoint' => $this->ReadPropertyString('Endpoint'),
            'state'    => !$this->ReadPropertyBoolean('Active') ? 'off' : ($err !== '' ? 'error' : ((int) $this->GetBuffer('LastUpdate') > 0 ? 'ok' : 'wait')),
            'error'    => $err,
            'updated'  => (int) $this->GetBuffer('LastUpdate'),
            'cycle'    => (int) $this->GetBuffer('CycleMs'),
            'rows'     => $rows,
        ], JSON_UNESCAPED_UNICODE);
    }

    private function pushVisualization(): void
    {
        $this->UpdateVisualizationValue($this->visualizationPayload());
    }
}
