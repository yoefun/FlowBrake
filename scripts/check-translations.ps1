param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function ConvertFrom-PoString([string]$Value) {
    return ($Value | ConvertFrom-Json)
}

function Get-EntryKey($Entry) {
    return $Entry.Context + [char]0 + $Entry.Id + [char]0 + $Entry.Plural
}

function Read-Catalog([string]$Path) {
    $entries = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $entry = @{ Context = ''; Id = ''; Plural = ''; Strings = @{}; Fuzzy = $false }
    $field = ''
    foreach ($line in (@(Get-Content -LiteralPath $Path -Encoding UTF8) + @(''))) {
        if ($line -match '^\s*$') {
            if ($entry.Id -ne '') {
                $key = Get-EntryKey $entry
                if ($entries.ContainsKey($key)) { throw "Duplicate catalog entry in ${Path}: $($entry.Id)" }
                $entries[$key] = $entry
            }
            $entry = @{ Context = ''; Id = ''; Plural = ''; Strings = @{}; Fuzzy = $false }
            $field = ''
        } elseif ($line -match '^#,.*\bfuzzy\b') {
            $entry.Fuzzy = $true
        } elseif ($line -match '^#') {
            continue
        } elseif ($line -match '^(msgctxt|msgid_plural|msgid|msgstr(?:\[\d+\])?)\s+(".*")$') {
            $field = $Matches[1]
            $value = ConvertFrom-PoString $Matches[2]
            switch ($field) {
                'msgctxt' { $entry.Context = $value }
                'msgid' { $entry.Id = $value }
                'msgid_plural' { $entry.Plural = $value }
                default { $entry.Strings[$field] = $value }
            }
        } elseif ($line -match '^(".*")$' -and $field -ne '') {
            $value = ConvertFrom-PoString $Matches[1]
            switch ($field) {
                'msgctxt' { $entry.Context += $value }
                'msgid' { $entry.Id += $value }
                'msgid_plural' { $entry.Plural += $value }
                default { $entry.Strings[$field] += $value }
            }
        } else {
            throw "Unsupported PO syntax in ${Path}: $line"
        }
    }
    return $entries
}

function Get-Parameters([string]$Text) {
    $position = 0
    $parameters = foreach ($match in [regex]::Matches($Text, '(?<!\{)\{([^{}]*)\}(?!\})')) {
        if ($match.Groups[1].Value -eq '') { "$position"; $position++ }
        else { $match.Groups[1].Value }
    }
    return (($parameters | Sort-Object -Unique) -join ',')
}

$uiRoot = Join-Path $RepositoryRoot 'crates/flowbrake-ui'
$sourceEntries = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
$trPattern = '@tr\(\s*("(?:\\.|[^"\\])*")\s*(?:=>\s*("(?:\\.|[^"\\])*"))?\s*(?:\|\s*("(?:\\.|[^"\\])*"))?'
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $uiRoot 'ui') -Filter '*.slint') {
    $source = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
    $calls = [regex]::Matches($source, $trPattern)
    if ([regex]::Matches($source, '@tr\(').Count -ne $calls.Count) {
        throw "Unrecognized translation call in $($file.Name)"
    }
    foreach ($call in $calls) {
        $first = ConvertFrom-PoString $call.Groups[1].Value
        $entry = @{ Context = ''; Id = $first; Plural = '' }
        if ($call.Groups[2].Success) {
            $entry.Context = $first
            $entry.Id = ConvertFrom-PoString $call.Groups[2].Value
        }
        if ($call.Groups[3].Success) { $entry.Plural = ConvertFrom-PoString $call.Groups[3].Value }
        $sourceEntries[(Get-EntryKey $entry)] = $entry
    }
}

$template = Read-Catalog (Join-Path $uiRoot 'lang/flowbrake-ui.pot')
$chinesePath = Join-Path $uiRoot 'lang/zh-CN/LC_MESSAGES/flowbrake-ui.po'
$chinese = Read-Catalog $chinesePath
$header = Get-Content -LiteralPath $chinesePath -Raw -Encoding UTF8
if ($header -notmatch 'Language: zh-CN\\n' -or $header -notmatch 'nplurals=1;\s*plural=0;') {
    throw 'Chinese catalog must declare zh-CN and one plural form.'
}
foreach ($catalog in @($template, $chinese)) {
    $drift = @(Compare-Object @($sourceEntries.Keys) @($catalog.Keys) -CaseSensitive)
    if ($drift.Count -ne 0) { throw "Source/catalog drift: $($drift | Out-String)" }
}
foreach ($key in $sourceEntries.Keys) {
    $entry = $chinese[$key]
    $expectedField = if ($entry.Plural -eq '') { 'msgstr' } else { 'msgstr[0]' }
    if ($entry.Fuzzy -or $entry.Strings.Count -ne 1 -or !$entry.Strings.ContainsKey($expectedField) -or $entry.Strings[$expectedField] -eq '') {
        throw "Missing, fuzzy, or invalid Chinese translation: $($entry.Id)"
    }
    $parameters = Get-Parameters $entry.Id
    if ($entry.Plural -ne '' -and $parameters -ne (Get-Parameters $entry.Plural)) {
        throw "Source plural parameters differ: $($entry.Id)"
    }
    if ($parameters -ne (Get-Parameters $entry.Strings[$expectedField])) {
        throw "Translation parameters differ: $($entry.Id)"
    }
}
Write-Host "Translation catalogs verified: $($sourceEntries.Count) entries (English / zh-CN)."
