-- emubot/modules/db.lua
-- SQLite persistence for EmuBot bot data (unique DB per server)

local mq = require('mq')

local table_unpack = table.unpack or unpack

-- Ensure Lua can find packages installed into <luaDir>/modules
local function _append_unique(list, suffix)
    if not list or not suffix or suffix == '' then return list end
    if not string.find(list, suffix, 1, true) then
        if list == '' then return suffix end
        return list .. ';' .. suffix
    end
    return list
end

local function _ensure_package_paths()
    local lua_dir = nil
    local ok, res = pcall(function()
        if type(mq.luaDir) == 'function' then return mq.luaDir() end
        return mq.luaDir
    end)
    if ok and res and res ~= '' then lua_dir = tostring(res) end
    if not lua_dir then return end
    package.path  = _append_unique(package.path  or '', lua_dir .. '/?.lua')
    package.path  = _append_unique(package.path  or '', lua_dir .. '/?/init.lua')
    package.path  = _append_unique(package.path  or '', lua_dir .. '/modules/?.lua')
    package.cpath = _append_unique(package.cpath or '', lua_dir .. '/modules/?.dll')
end

_ensure_package_paths()
local sqlite3 = require('lsqlite3')

local M = {}
M._db = nil
M._db_path = nil
M._debug = false

local run_migrations  -- forward declaration so helpers can request a schema fix

-- Resolve current character (owner) name for scoping
local function get_owner_name()
    if mq and mq.TLO and mq.TLO.Me then
        local ok, name = pcall(function()
            if mq.TLO.Me.CleanName and mq.TLO.Me.CleanName() then return mq.TLO.Me.CleanName() end
            if mq.TLO.Me.Name and mq.TLO.Me.Name() then return mq.TLO.Me.Name() end
            return nil
        end)
        if ok and name and name ~= '' then return tostring(name) end
    end
    return 'unknown'
end

local function table_exists(name)
    if not M._db or not name then return false end
    local stmt = M._db:prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
    if not stmt then return false end
    stmt:bind_values(name)
    local rc = stmt:step()
    local exists = rc == sqlite3.ROW
    stmt:finalize()
    return exists
end

function M.set_debug(enabled)
    M._debug = not not enabled
    printf('[EmuBot][DB] Debug logging %s', M._debug and 'ENABLED' or 'DISABLED')
    if M._debug and M._db then
        -- Dump items schema for quick verification
        printf('[EmuBot][DB] DB Path: %s', tostring(M._db_path))
        printf('[EmuBot][DB] items_catalog schema:')
        for row in M._db:nrows("PRAGMA table_info('items_catalog');") do
            printf('  - %s (%s)', tostring(row.name), tostring(row.type))
        end
        printf('[EmuBot][DB] bot_equipment schema:')
        for row in M._db:nrows("PRAGMA table_info('bot_equipment');") do
            printf('  - %s (%s)', tostring(row.name), tostring(row.type))
        end
        printf('[EmuBot][DB] bots schema:')
        for row in M._db:nrows("PRAGMA table_info('bots');") do
            printf('  - %s (%s)', tostring(row.name), tostring(row.type))
        end
    end
end

local function dump_schema_if_debug()
    if not M._debug or not M._db then return end
    printf('[EmuBot][DB] DB Path: %s', tostring(M._db_path))
    printf('[EmuBot][DB] items_catalog schema:')
    for row in M._db:nrows("PRAGMA table_info('items_catalog');") do
        printf('  - %s (%s)', tostring(row.name), tostring(row.type))
    end
    printf('[EmuBot][DB] bot_equipment schema:')
    for row in M._db:nrows("PRAGMA table_info('bot_equipment');") do
        printf('  - %s (%s)', tostring(row.name), tostring(row.type))
    end
    printf('[EmuBot][DB] bots schema:')
    for row in M._db:nrows("PRAGMA table_info('bots');") do
        printf('  - %s (%s)', tostring(row.name), tostring(row.type))
    end
end

local function printf(fmt, ...)
    if mq.printf then mq.printf(fmt, ...) else print(string.format(fmt, ...)) end
end

local function normalizePathSeparators(path)
    return path and path:gsub('\\\\', '/') or nil
end

local function trimTrailingSlash(path)
    if not path then return nil end
    return path:gsub('/+$', '')
end

local function detectResourcesDir()
    -- Try MacroQuest.Resources path first
    if mq and mq.TLO and mq.TLO.MacroQuest and mq.TLO.MacroQuest.Path then
        local ok, result = pcall(function()
            local tlo = mq.TLO.MacroQuest.Path('Resources')
            if tlo and tlo() and tlo() ~= '' then return tlo() end
            return nil
        end)
        if ok and result and result ~= '' then
            local normalized = trimTrailingSlash(normalizePathSeparators(tostring(result)))
            if normalized and normalized ~= '' then return normalized end
        end
    end
    -- Fallback: derive from luaDir
    if mq and mq.luaDir then
        local ok, result = pcall(function()
            if type(mq.luaDir) == 'function' then return mq.luaDir() end
            return mq.luaDir
        end)
        if ok and result and result ~= '' then
            local normalized = trimTrailingSlash(normalizePathSeparators(tostring(result)))
            if normalized then
                local root = normalized:match('^(.*)/lua$')
                if root and root ~= '' then
                    return root .. '/Resources'
                end
            end
        end
    end
    return nil
end

local function get_server_name()
    if mq and mq.TLO and mq.TLO.EverQuest and mq.TLO.EverQuest.Server then
        local ok, server = pcall(function() return mq.TLO.EverQuest.Server() end)
        if ok and server and server ~= '' then return tostring(server) end
    end
    return 'default'
end

local function ensure_parent_dir_exists(path)
    -- Best effort: Lua standard libs don’t have mkdir; MacroQuest usually ensures Resources exists.
    -- We’ll no-op here assuming Resources exists.
    return true
end

local function open_db()
    local resources = detectResourcesDir() or '.'
    local server = get_server_name()
    local filename = string.format('emubot_%s.sqlite', server:gsub('[^%w%-_%.]', '_'))
    local db_path = resources .. '/' .. filename
    ensure_parent_dir_exists(db_path)

    local db = sqlite3.open(db_path)
    if not db then
        return false, 'failed to open sqlite database'
    end

    -- Pragmas for better durability/performance
    db:exec('PRAGMA journal_mode=WAL;')
    db:exec('PRAGMA synchronous=NORMAL;')

    M._db = db
    M._db_path = db_path
    return true
end

local function exec_ddl()
    if M._db then
        if table_exists('bot_equipment') then
            -- already migrated
        elseif table_exists('items') then
            M._db:exec('ALTER TABLE items RENAME TO legacy_items;')
        end
    end
    local ddl = [[
    CREATE TABLE IF NOT EXISTS bots (
        name TEXT PRIMARY KEY,
        level INTEGER,
        class TEXT,
        race TEXT,
        gender TEXT,
        owner TEXT,
        last_updated INTEGER
    );

    CREATE TABLE IF NOT EXISTS items_catalog (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_id INTEGER,
        name TEXT,
        icon INTEGER,
        ac INTEGER,
        hp INTEGER,
        mana INTEGER,
        endurance INTEGER,
        damage INTEGER,
        delay INTEGER,
        str INTEGER,
        dex INTEGER,
        agi INTEGER,
        sta INTEGER,
        int INTEGER,
        wis INTEGER,
        cha INTEGER,
        heroicStr INTEGER,
        heroicDex INTEGER,
        heroicAgi INTEGER,
        heroicSta INTEGER,
        heroicInt INTEGER,
        heroicWis INTEGER,
        heroicCha INTEGER,
        svMagic INTEGER,
        svFire INTEGER,
        svCold INTEGER,
        svPoison INTEGER,
        svDisease INTEGER,
        svCorruption INTEGER,
        attack INTEGER,
        haste INTEGER,
        itemlink TEXT,
        rawline TEXT,
        created_at INTEGER DEFAULT (strftime('%s','now')),
        updated_at INTEGER DEFAULT (strftime('%s','now'))
    );

    CREATE TABLE IF NOT EXISTS bot_equipment (
        owner TEXT NOT NULL,
        bot_name TEXT NOT NULL,
        location TEXT NOT NULL,
        slotid INTEGER,
        slotname TEXT,
        catalog_id INTEGER,
        itemlink TEXT,
        rawline TEXT,
        qty INTEGER,
        nodrop INTEGER,
        stackSize INTEGER,
        charges INTEGER,
        aug1Name TEXT, aug1link TEXT, aug1Icon INTEGER,
        aug2Name TEXT, aug2link TEXT, aug2Icon INTEGER,
        aug3Name TEXT, aug3link TEXT, aug3Icon INTEGER,
        aug4Name TEXT, aug4link TEXT, aug4Icon INTEGER,
        aug5Name TEXT, aug5link TEXT, aug5Icon INTEGER,
        aug6Name TEXT, aug6link TEXT, aug6Icon INTEGER,
        PRIMARY KEY (owner, bot_name, location, slotid),
        FOREIGN KEY (catalog_id) REFERENCES items_catalog(id)
    );

    CREATE INDEX IF NOT EXISTS idx_items_catalog_itemid ON items_catalog(item_id);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_items_catalog_itemid_unique ON items_catalog(item_id) WHERE item_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_bot_equipment_catalog ON bot_equipment(catalog_id);
    CREATE INDEX IF NOT EXISTS idx_bot_equipment_bot ON bot_equipment(owner, bot_name);

    CREATE TABLE IF NOT EXISTS bot_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        created_at INTEGER DEFAULT (strftime('%s','now')),
        updated_at INTEGER DEFAULT (strftime('%s','now'))
    );

    CREATE TABLE IF NOT EXISTS bot_group_members (
        group_id INTEGER NOT NULL,
        bot_name TEXT NOT NULL,
        added_at INTEGER DEFAULT (strftime('%s','now')),
        PRIMARY KEY (group_id, bot_name),
        FOREIGN KEY (group_id) REFERENCES bot_groups(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_group_members_group ON bot_group_members(group_id);
    CREATE INDEX IF NOT EXISTS idx_group_members_bot ON bot_group_members(bot_name);
    ]]
    return M._db:exec(ddl) == sqlite3.OK
end

-- Lightweight migrations: ensure new columns exist on existing databases
local function column_exists(table_name, column_name)
    local exists = false
    for row in M._db:nrows(string.format("PRAGMA table_info('%s');", table_name)) do
        if tostring(row.name) == tostring(column_name) then
            exists = true
            break
        end
    end
    return exists
end

local function to_int(value)
    if value == nil then return nil end
    local num = tonumber(value)
    if not num then return nil end
    if num >= 0 then
        return math.floor(num + 0.0000001)
    else
        return math.ceil(num - 0.0000001)
    end
end

local function sanitize_text(value)
    if not value then return nil end
    local txt = tostring(value)
    if txt == '' then return nil end
    return txt
end

local function ensure_catalog_entry(it)
    if not it then return nil end
    local item_id = to_int(it.itemID or it.item_id)
    if item_id and item_id <= 0 then item_id = nil end
    local name = sanitize_text(it.name) or sanitize_text(it.itemName) or sanitize_text(it.slotname) or 'Unknown Item'
    local icon = to_int(it.icon or it.iconID)
    -- Basic stats
    local ac = to_int(it.ac)
    local hp = to_int(it.hp)
    local mana = to_int(it.mana)
    local endurance = to_int(it.endurance)
    local damage = to_int(it.damage)
    local delay = to_int(it.delay)
    -- Core attributes
    local str = to_int(it.str)
    local dex = to_int(it.dex)
    local agi = to_int(it.agi)
    local sta = to_int(it.sta)
    local int = to_int(it.int)
    local wis = to_int(it.wis)
    local cha = to_int(it.cha)
    -- Heroic stats
    local heroicStr = to_int(it.heroicStr)
    local heroicDex = to_int(it.heroicDex)
    local heroicAgi = to_int(it.heroicAgi)
    local heroicSta = to_int(it.heroicSta)
    local heroicInt = to_int(it.heroicInt)
    local heroicWis = to_int(it.heroicWis)
    local heroicCha = to_int(it.heroicCha)
    -- Resistances
    local svMagic = to_int(it.svMagic)
    local svFire = to_int(it.svFire)
    local svCold = to_int(it.svCold)
    local svPoison = to_int(it.svPoison)
    local svDisease = to_int(it.svDisease)
    local svCorruption = to_int(it.svCorruption)
    -- Combat stats
    local attack = to_int(it.attack)
    local haste = to_int(it.haste)
    local itemlink = sanitize_text(it.itemlink)
    local rawline = sanitize_text(it.rawline)

    local catalog_id
    if item_id then
        local stmt = M._db:prepare('SELECT id FROM items_catalog WHERE item_id = ? LIMIT 1')
        if stmt then
            stmt:bind_values(item_id)
            local rc = stmt:step()
            if rc == sqlite3.ROW then
                catalog_id = stmt:get_value(0)
            end
            stmt:finalize()
        end
    end

    if not catalog_id then
        local stmt = M._db:prepare('SELECT id FROM items_catalog WHERE item_id IS NULL AND name = ? AND IFNULL(icon,0) = ? LIMIT 1')
        if stmt then
            stmt:bind_values(name, icon or 0)
            local rc = stmt:step()
            if rc == sqlite3.ROW then
                catalog_id = stmt:get_value(0)
            end
            stmt:finalize()
        end
    end

    if not catalog_id then
        local insert_sql = [[INSERT INTO items_catalog(
            item_id, name, icon, ac, hp, mana, endurance, damage, delay,
            str, dex, agi, sta, int, wis, cha,
            heroicStr, heroicDex, heroicAgi, heroicSta, heroicInt, heroicWis, heroicCha,
            svMagic, svFire, svCold, svPoison, svDisease, svCorruption,
            attack, haste, itemlink, rawline,
            created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, strftime('%s','now'), strftime('%s','now'))]]
        local insert_stmt = M._db:prepare(insert_sql)
        if not insert_stmt then
            if run_migrations then run_migrations() end
            insert_stmt = M._db:prepare(insert_sql)
        end
        if insert_stmt then
            insert_stmt:bind_values(
                item_id, name, icon, ac, hp, mana, endurance, damage, delay,
                str, dex, agi, sta, int, wis, cha,
                heroicStr, heroicDex, heroicAgi, heroicSta, heroicInt, heroicWis, heroicCha,
                svMagic, svFire, svCold, svPoison, svDisease, svCorruption,
                attack, haste, itemlink, rawline
            )
            local rc = insert_stmt:step()
            if rc ~= sqlite3.DONE then
                insert_stmt:finalize()
                return nil
            end
            insert_stmt:finalize()
            catalog_id = M._db:last_insert_rowid()
            return catalog_id
        end
    end

    if not catalog_id then return nil end

    local update_sql = [[UPDATE items_catalog SET
        item_id = CASE WHEN (item_id IS NULL OR item_id = 0) AND ? IS NOT NULL THEN ? ELSE item_id END,
        icon = CASE WHEN (icon IS NULL OR icon = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE icon END,
        ac = CASE WHEN (ac IS NULL OR ac = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE ac END,
        hp = CASE WHEN (hp IS NULL OR hp = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE hp END,
        mana = CASE WHEN (mana IS NULL OR mana = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE mana END,
        endurance = CASE WHEN (endurance IS NULL OR endurance = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE endurance END,
        damage = CASE WHEN (damage IS NULL OR damage = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE damage END,
        delay = CASE WHEN (delay IS NULL OR delay = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE delay END,
        str = CASE WHEN (str IS NULL OR str = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE str END,
        dex = CASE WHEN (dex IS NULL OR dex = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE dex END,
        agi = CASE WHEN (agi IS NULL OR agi = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE agi END,
        sta = CASE WHEN (sta IS NULL OR sta = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE sta END,
        int = CASE WHEN (int IS NULL OR int = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE int END,
        wis = CASE WHEN (wis IS NULL OR wis = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE wis END,
        cha = CASE WHEN (cha IS NULL OR cha = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE cha END,
        heroicStr = CASE WHEN (heroicStr IS NULL OR heroicStr = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE heroicStr END,
        heroicDex = CASE WHEN (heroicDex IS NULL OR heroicDex = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE heroicDex END,
        heroicAgi = CASE WHEN (heroicAgi IS NULL OR heroicAgi = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE heroicAgi END,
        heroicSta = CASE WHEN (heroicSta IS NULL OR heroicSta = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE heroicSta END,
        heroicInt = CASE WHEN (heroicInt IS NULL OR heroicInt = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE heroicInt END,
        heroicWis = CASE WHEN (heroicWis IS NULL OR heroicWis = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE heroicWis END,
        heroicCha = CASE WHEN (heroicCha IS NULL OR heroicCha = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE heroicCha END,
        svMagic = CASE WHEN (svMagic IS NULL OR svMagic = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE svMagic END,
        svFire = CASE WHEN (svFire IS NULL OR svFire = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE svFire END,
        svCold = CASE WHEN (svCold IS NULL OR svCold = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE svCold END,
        svPoison = CASE WHEN (svPoison IS NULL OR svPoison = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE svPoison END,
        svDisease = CASE WHEN (svDisease IS NULL OR svDisease = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE svDisease END,
        svCorruption = CASE WHEN (svCorruption IS NULL OR svCorruption = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE svCorruption END,
        attack = CASE WHEN (attack IS NULL OR attack = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE attack END,
        haste = CASE WHEN (haste IS NULL OR haste = 0) AND ? IS NOT NULL AND ? <> 0 THEN ? ELSE haste END,
        name = CASE WHEN (name IS NULL OR name = '') AND ? IS NOT NULL AND ? <> '' THEN ? ELSE name END,
        itemlink = CASE WHEN (itemlink IS NULL OR itemlink = '') AND ? IS NOT NULL AND ? <> '' THEN ? ELSE itemlink END,
        rawline = CASE WHEN (rawline IS NULL OR rawline = '') AND ? IS NOT NULL AND ? <> '' THEN ? ELSE rawline END,
        updated_at = strftime('%s','now')
        WHERE id = ?]]
    local update_stmt = M._db:prepare(update_sql)
    if not update_stmt then
        if run_migrations then run_migrations() end
        update_stmt = M._db:prepare(update_sql)
    end
    if update_stmt then
        update_stmt:bind_values(
            item_id, item_id,
            icon, icon, icon,
            ac, ac, ac,
            hp, hp, hp,
            mana, mana, mana,
            endurance, endurance, endurance,
            damage, damage, damage,
            delay, delay, delay,
            str, str, str,
            dex, dex, dex,
            agi, agi, agi,
            sta, sta, sta,
            int, int, int,
            wis, wis, wis,
            cha, cha, cha,
            heroicStr, heroicStr, heroicStr,
            heroicDex, heroicDex, heroicDex,
            heroicAgi, heroicAgi, heroicAgi,
            heroicSta, heroicSta, heroicSta,
            heroicInt, heroicInt, heroicInt,
            heroicWis, heroicWis, heroicWis,
            heroicCha, heroicCha, heroicCha,
            svMagic, svMagic, svMagic,
            svFire, svFire, svFire,
            svCold, svCold, svCold,
            svPoison, svPoison, svPoison,
            svDisease, svDisease, svDisease,
            svCorruption, svCorruption, svCorruption,
            attack, attack, attack,
            haste, haste, haste,
            name, name, name,
            itemlink, itemlink, itemlink,
            rawline, rawline, rawline,
            catalog_id
        )
        update_stmt:step()
        update_stmt:finalize()
    end

    return catalog_id
end

local function migrate_legacy_items()
    if not table_exists('legacy_items') then return end

    printf('[EmuBot][DB] Migrating legacy items table to catalog/equipment schema...')

    local ownerFallback = get_owner_name()
    local insert_stmt = M._db:prepare([[INSERT OR REPLACE INTO bot_equipment(
        owner, bot_name, location, slotid, slotname, catalog_id,
        itemlink, rawline, qty, nodrop, stackSize, charges,
        aug1Name, aug1link, aug1Icon,
        aug2Name, aug2link, aug2Icon,
        aug3Name, aug3link, aug3Icon,
        aug4Name, aug4link, aug4Icon,
        aug5Name, aug5link, aug5Icon,
        aug6Name, aug6link, aug6Icon
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)]])

    for row in M._db:nrows('SELECT * FROM legacy_items;') do
        local catalog_id = nil
        if row then
            catalog_id = ensure_catalog_entry(row)
        end
        local owner = row.owner or ownerFallback
        if insert_stmt then
            insert_stmt:bind_values(
                owner,
                row.bot_name,
                row.location or 'Equipped',
                tonumber(row.slotid) or 0,
                row.slotname,
                catalog_id,
                row.itemlink,
                row.rawline,
                tonumber(row.qty),
                tonumber(row.nodrop),
                tonumber(row.stackSize),
                tonumber(row.charges),
                row.aug1Name, row.aug1link, tonumber(row.aug1Icon),
                row.aug2Name, row.aug2link, tonumber(row.aug2Icon),
                row.aug3Name, row.aug3link, tonumber(row.aug3Icon),
                row.aug4Name, row.aug4link, tonumber(row.aug4Icon),
                row.aug5Name, row.aug5link, tonumber(row.aug5Icon),
                row.aug6Name, row.aug6link, tonumber(row.aug6Icon)
            )
            local rc = insert_stmt:step()
            if rc ~= sqlite3.DONE then
                printf('[EmuBot][DB] Warning: failed to migrate legacy item for %s slot %s: %s',
                    tostring(row.bot_name), tostring(row.slotid), tostring(last_error()))
            end
            insert_stmt:reset()
        end
    end

    if insert_stmt then insert_stmt:finalize() end
    M._db:exec('DROP TABLE IF EXISTS legacy_items;')
end

local function run_migrations_impl()
    if not column_exists('bots', 'owner') then
        M._db:exec('ALTER TABLE bots ADD COLUMN owner TEXT;')
    end

    -- Migrate items_catalog to include advanced stats
    if table_exists('items_catalog') then
        -- Add endurance if missing
        if not column_exists('items_catalog', 'endurance') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN endurance INTEGER;')
        end

        -- Add core attribute columns if missing
        if not column_exists('items_catalog', 'str') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN str INTEGER;')
        end
        if not column_exists('items_catalog', 'dex') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN dex INTEGER;')
        end
        if not column_exists('items_catalog', 'agi') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN agi INTEGER;')
        end
        if not column_exists('items_catalog', 'sta') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN sta INTEGER;')
        end
        if not column_exists('items_catalog', 'int') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN int INTEGER;')
        end
        if not column_exists('items_catalog', 'wis') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN wis INTEGER;')
        end
        if not column_exists('items_catalog', 'cha') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN cha INTEGER;')
        end

        -- Add heroic stat columns if missing
        if not column_exists('items_catalog', 'heroicStr') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN heroicStr INTEGER;')
        end
        if not column_exists('items_catalog', 'heroicDex') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN heroicDex INTEGER;')
        end
        if not column_exists('items_catalog', 'heroicAgi') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN heroicAgi INTEGER;')
        end
        if not column_exists('items_catalog', 'heroicSta') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN heroicSta INTEGER;')
        end
        if not column_exists('items_catalog', 'heroicInt') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN heroicInt INTEGER;')
        end
        if not column_exists('items_catalog', 'heroicWis') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN heroicWis INTEGER;')
        end
        if not column_exists('items_catalog', 'heroicCha') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN heroicCha INTEGER;')
        end

        -- Add resistance columns if missing
        if not column_exists('items_catalog', 'svMagic') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN svMagic INTEGER;')
        end
        if not column_exists('items_catalog', 'svFire') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN svFire INTEGER;')
        end
        if not column_exists('items_catalog', 'svCold') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN svCold INTEGER;')
        end
        if not column_exists('items_catalog', 'svPoison') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN svPoison INTEGER;')
        end
        if not column_exists('items_catalog', 'svDisease') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN svDisease INTEGER;')
        end
        if not column_exists('items_catalog', 'svCorruption') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN svCorruption INTEGER;')
        end

        -- Add combat stat columns if missing
        if not column_exists('items_catalog', 'attack') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN attack INTEGER;')
        end
        if not column_exists('items_catalog', 'haste') then
            M._db:exec('ALTER TABLE items_catalog ADD COLUMN haste INTEGER;')
        end
    end

    migrate_legacy_items()
end

run_migrations = run_migrations_impl

function M.init()
    local ok, err = open_db()
    if not ok then return false, err end
    local okddl = exec_ddl()
    if not okddl then return false, 'failed to create schema' end
    -- Ensure schema migrations for existing DBs
    run_migrations()
    dump_schema_if_debug()
    printf('[EmuBot][DB] Using %s', tostring(M._db_path))
    return true
end

-- Expose a manual migration trigger for troubleshooting
function M.migrate()
    if not M._db then
        local ok, err = open_db()
        if not ok then return false, err end
    end
    local okddl = exec_ddl()
    if not okddl then return false, 'failed to create schema' end
    run_migrations()
    dump_schema_if_debug()
    return true
end

function M.purge_all()
    if not M._db then
        local ok, err = open_db()
        if not ok then return false, err end
    end

    local drop_sql = [[
    DROP TABLE IF EXISTS bot_group_members;
    DROP TABLE IF EXISTS bot_groups;
    DROP TABLE IF EXISTS bot_equipment;
    DROP TABLE IF EXISTS items_catalog;
    DROP TABLE IF EXISTS bots;
    DROP TABLE IF EXISTS legacy_items;
    ]]

    local rc = M._db:exec(drop_sql)
    if rc ~= sqlite3.OK then
        return false, last_error()
    end

    local okddl = exec_ddl()
    if not okddl then
        return false, 'failed to recreate schema'
    end
    run_migrations()
    return true
end

local function upsert_bot(botName, meta)
    local owner = get_owner_name()
    local stmt = M._db:prepare([[INSERT INTO bots(name, level, class, race, gender, owner, last_updated)
        VALUES(?,?,?,?,?,?, strftime('%s','now'))
        ON CONFLICT(name) DO UPDATE SET
            level=excluded.level,
            class=excluded.class,
            race=excluded.race,
            gender=excluded.gender,
            owner=excluded.owner,
            last_updated=strftime('%s','now')
    ]])
    if not stmt then
        -- Retry after running migrations in case owner column is missing
        run_migrations()
        stmt = M._db:prepare([[INSERT INTO bots(name, level, class, race, gender, owner, last_updated)
        VALUES(?,?,?,?,?,?, strftime('%s','now'))
        ON CONFLICT(name) DO UPDATE SET
            level=excluded.level,
            class=excluded.class,
            race=excluded.race,
            gender=excluded.gender,
            owner=excluded.owner,
            last_updated=strftime('%s','now')
    ]])
    end
    if not stmt then return false, last_error() end
    stmt:bind_values(
        botName,
        meta and meta.Level or nil,
        meta and meta.Class or nil,
        meta and meta.Race or nil,
        meta and meta.Gender or nil,
        owner
    )
    local rc = stmt:step()
    local ok = (rc == sqlite3.DONE)
    local err = not ok and last_error() or nil
    stmt:finalize()
    if not ok then return false, err end
    return true
end

local function last_error()
    if M._db and M._db.errmsg then
        return M._db:errmsg()
    end
    return 'unknown sqlite error'
end

local function bind_owner_and_names(stmt, owner, botNames)
    local binds = { owner }
    if botNames then
        for _, name in ipairs(botNames) do
            table.insert(binds, name)
        end
    end
    stmt:bind_values(table_unpack(binds))
end

local function delete_missing_bots(tableName, columnName, owner, botNames)
    local query
    if botNames and #botNames > 0 then
        local placeholders = {}
        for _ = 1, #botNames do table.insert(placeholders, '?') end
        query = string.format('DELETE FROM %s WHERE owner = ? AND %s NOT IN (%s)',
            tableName, columnName, table.concat(placeholders, ','))
    else
        query = string.format('DELETE FROM %s WHERE owner = ?', tableName)
    end

    local stmt = M._db:prepare(query)
    if not stmt then
        return false, last_error()
    end
    bind_owner_and_names(stmt, owner, botNames)
    local rc = stmt:step()
    stmt:finalize()
    if rc ~= sqlite3.DONE then
        return false, last_error()
    end
    return true
end

function M.prune_missing_bots(owner, botNames)
    if not M._db then
        local ok, err = open_db()
        if not ok then return false, err end
    end

    owner = owner or get_owner_name()
    local ok1, err1 = delete_missing_bots('bot_equipment', 'bot_name', owner, botNames)
    if not ok1 then return false, err1 end
    local ok2, err2 = delete_missing_bots('bots', 'name', owner, botNames)
    if not ok2 then return false, err2 end
    return true
end

local function insert_item(botName, location, it)
    if M._debug then
        printf('[EmuBot][DB][insert] bot=%s loc=%s slot=%s name="%s" itemID=%s',
            tostring(botName), tostring(location), tostring(it.slotid), tostring(it.name or ''), tostring(it.itemID or 'nil'))
    end

    local owner = get_owner_name()
    local catalog_id = ensure_catalog_entry(it)

    local stmt = M._db:prepare([[INSERT OR REPLACE INTO bot_equipment(
        owner, bot_name, location, slotid, slotname, catalog_id,
        itemlink, rawline, qty, nodrop, stackSize, charges,
        aug1Name, aug1link, aug1Icon,
        aug2Name, aug2link, aug2Icon,
        aug3Name, aug3link, aug3Icon,
        aug4Name, aug4link, aug4Icon,
        aug5Name, aug5link, aug5Icon,
        aug6Name, aug6link, aug6Icon
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)]])
    if not stmt then
        run_migrations()
        stmt = M._db:prepare([[INSERT OR REPLACE INTO bot_equipment(
            owner, bot_name, location, slotid, slotname, catalog_id,
            itemlink, rawline, qty, nodrop, stackSize, charges,
            aug1Name, aug1link, aug1Icon,
            aug2Name, aug2link, aug2Icon,
            aug3Name, aug3link, aug3Icon,
            aug4Name, aug4link, aug4Icon,
            aug5Name, aug5link, aug5Icon,
            aug6Name, aug6link, aug6Icon
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)]])
    end
    if not stmt then
        return false, 'bot_equipment insert prepare failed'
    end

    stmt:bind_values(
        owner,
        botName,
        location or 'Equipped',
        to_int(it.slotid) or 0,
        it.slotname,
        catalog_id,
        it.itemlink,
        it.rawline,
        to_int(it.qty),
        to_int(it.nodrop),
        to_int(it.stackSize),
        to_int(it.charges),
        it.aug1Name, it.aug1link, to_int(it.aug1Icon),
        it.aug2Name, it.aug2link, to_int(it.aug2Icon),
        it.aug3Name, it.aug3link, to_int(it.aug3Icon),
        it.aug4Name, it.aug4link, to_int(it.aug4Icon),
        it.aug5Name, it.aug5link, to_int(it.aug5Icon),
        it.aug6Name, it.aug6link, to_int(it.aug6Icon)
    )

    local rc = stmt:step()
    local ok = (rc == sqlite3.DONE)
    local err = not ok and last_error() or nil
    stmt:finalize()
    if not ok then return false, err end
    return true
end

function M.save_bot_inventory(botName, data, meta)
    if not M._db then return false, 'db not initialized' end
    if not botName or not data then return false, 'bad args' end
    if M._debug then
        local eqc = (data.equipped and #data.equipped) or 0
        printf('[EmuBot][DB][save] bot=%s equipped=%d', tostring(botName), eqc)
    end
    M._db:exec('BEGIN;')
    local ok1, e1 = upsert_bot(botName, meta or {})
    if not ok1 then M._db:exec('ROLLBACK;'); return false, 'upsert bot failed: ' .. tostring(e1) end

    -- Replace Equipped items for this bot (scoped by owner)
    local owner = get_owner_name()
    local del = M._db:prepare('DELETE FROM bot_equipment WHERE owner=? AND bot_name=? AND location=?')
    del:bind_values(owner, botName, 'Equipped')
    del:step()
    del:finalize()

    for _, it in ipairs((data.equipped) or {}) do
        local ok, ierr = insert_item(botName, 'Equipped', it)
        if not ok then M._db:exec('ROLLBACK;'); return false, 'insert item failed: ' .. tostring(ierr) end
    end

    -- Future: bags/bank persistence can be added similarly

    M._db:exec('COMMIT;')
    if M._debug then printf('[EmuBot][DB][save] COMMIT bot=%s', tostring(botName)) end
    return true
end

local function collect_rows(query, bind)
    local t = {}
    local stmt = M._db:prepare(query)
    if not stmt then return t end
    if bind then bind(stmt) end
    while true do
        local rc = stmt:step()
        if rc == sqlite3.ROW then
            local row = {}
            local n = stmt:columns()
            for i = 0, n - 1 do
                local name = stmt:get_name(i) or tostring(i)
                row[name] = stmt:get_value(i)
            end
            table.insert(t, row)
        elseif rc == sqlite3.DONE then
            break
        else
            break
        end
    end
    stmt:finalize()
    return t
end

function M.load_all()
    if not M._db then return {} end
    local owner = get_owner_name()
    local bots = collect_rows('SELECT name, level, class, race, gender FROM bots WHERE owner = ?', function(s)
        s:bind_values(owner)
    end)
    local result = {}
    for _, b in ipairs(bots) do
        result[b.name] = {
            name = b.name,
            level = tonumber(b.level) or nil,
            class = b.class,
            race = b.race,
            gender = b.gender,
            equipped = {},
            bags = {},
            bank = {},
        }
        local items = collect_rows([[SELECT
            be.slotid, be.slotname, be.itemlink, be.rawline,
            be.qty, be.nodrop, be.stackSize, be.charges,
            be.aug1Name, be.aug1link, be.aug1Icon,
            be.aug2Name, be.aug2link, be.aug2Icon,
            be.aug3Name, be.aug3link, be.aug3Icon,
            be.aug4Name, be.aug4link, be.aug4Icon,
            be.aug5Name, be.aug5link, be.aug5Icon,
            be.aug6Name, be.aug6link, be.aug6Icon,
            ic.item_id AS catalog_item_id,
            ic.name AS catalog_name,
            ic.icon AS catalog_icon,
            ic.ac AS catalog_ac,
            ic.hp AS catalog_hp,
            ic.mana AS catalog_mana,
            ic.endurance AS catalog_endurance,
            ic.damage AS catalog_damage,
            ic.delay AS catalog_delay,
            ic.str AS catalog_str,
            ic.dex AS catalog_dex,
            ic.agi AS catalog_agi,
            ic.sta AS catalog_sta,
            ic.int AS catalog_int,
            ic.wis AS catalog_wis,
            ic.cha AS catalog_cha,
            ic.heroicStr AS catalog_heroicStr,
            ic.heroicDex AS catalog_heroicDex,
            ic.heroicAgi AS catalog_heroicAgi,
            ic.heroicSta AS catalog_heroicSta,
            ic.heroicInt AS catalog_heroicInt,
            ic.heroicWis AS catalog_heroicWis,
            ic.heroicCha AS catalog_heroicCha,
            ic.svMagic AS catalog_svMagic,
            ic.svFire AS catalog_svFire,
            ic.svCold AS catalog_svCold,
            ic.svPoison AS catalog_svPoison,
            ic.svDisease AS catalog_svDisease,
            ic.svCorruption AS catalog_svCorruption,
            ic.attack AS catalog_attack,
            ic.haste AS catalog_haste
        FROM bot_equipment be
        LEFT JOIN items_catalog ic ON ic.id = be.catalog_id
        WHERE be.owner=? AND be.bot_name=? AND be.location=?
        ORDER BY be.slotid]], function(s)
            s:bind_values(owner, b.name, 'Equipped')
        end)
        for _, r in ipairs(items) do
            table.insert(result[b.name].equipped, {
                name = r.catalog_name or 'Unknown Item',
                slotid = tonumber(r.slotid),
                slotname = r.slotname,
                itemlink = r.itemlink,
                rawline = r.rawline,
                itemID = tonumber(r.catalog_item_id),
                icon = to_int(r.catalog_icon) or 0,
                -- Basic stats
                ac = tonumber(r.catalog_ac) or 0,
                hp = tonumber(r.catalog_hp) or 0,
                mana = tonumber(r.catalog_mana) or 0,
                endurance = tonumber(r.catalog_endurance) or 0,
                damage = tonumber(r.catalog_damage) or 0,
                delay = tonumber(r.catalog_delay) or 0,
                -- Core attributes
                str = tonumber(r.catalog_str) or 0,
                dex = tonumber(r.catalog_dex) or 0,
                agi = tonumber(r.catalog_agi) or 0,
                sta = tonumber(r.catalog_sta) or 0,
                int = tonumber(r.catalog_int) or 0,
                wis = tonumber(r.catalog_wis) or 0,
                cha = tonumber(r.catalog_cha) or 0,
                -- Heroic stats
                heroicStr = tonumber(r.catalog_heroicStr) or 0,
                heroicDex = tonumber(r.catalog_heroicDex) or 0,
                heroicAgi = tonumber(r.catalog_heroicAgi) or 0,
                heroicSta = tonumber(r.catalog_heroicSta) or 0,
                heroicInt = tonumber(r.catalog_heroicInt) or 0,
                heroicWis = tonumber(r.catalog_heroicWis) or 0,
                heroicCha = tonumber(r.catalog_heroicCha) or 0,
                -- Resistances
                svMagic = tonumber(r.catalog_svMagic) or 0,
                svFire = tonumber(r.catalog_svFire) or 0,
                svCold = tonumber(r.catalog_svCold) or 0,
                svPoison = tonumber(r.catalog_svPoison) or 0,
                svDisease = tonumber(r.catalog_svDisease) or 0,
                svCorruption = tonumber(r.catalog_svCorruption) or 0,
                -- Combat stats
                attack = tonumber(r.catalog_attack) or 0,
                haste = tonumber(r.catalog_haste) or 0,
                qty = tonumber(r.qty) or 0,
                nodrop = tonumber(r.nodrop) or 0,
                stackSize = tonumber(r.stackSize),
                charges = tonumber(r.charges),
                aug1Name = r.aug1Name, aug1link = r.aug1link, aug1Icon = tonumber(r.aug1Icon),
                aug2Name = r.aug2Name, aug2link = r.aug2link, aug2Icon = tonumber(r.aug2Icon),
                aug3Name = r.aug3Name, aug3link = r.aug3link, aug3Icon = tonumber(r.aug3Icon),
                aug4Name = r.aug4Name, aug4link = r.aug4link, aug4Icon = tonumber(r.aug4Icon),
                aug5Name = r.aug5Name, aug5link = r.aug5link, aug5Icon = tonumber(r.aug5Icon),
                aug6Name = r.aug6Name, aug6link = r.aug6link, aug6Icon = tonumber(r.aug6Icon)
            })
        end
    end
    return result
end

-- Bot Group Management Functions

function M.create_group(name, description)
    if not M._db then return false, 'db not initialized' end
    if not name or name == '' then return false, 'group name required' end
    
    local stmt = M._db:prepare('INSERT INTO bot_groups (name, description) VALUES (?, ?)')
    if not stmt then return false, 'prepare failed' end
    
    stmt:bind_values(name, description or '')
    local rc = stmt:step()
    local ok = (rc == sqlite3.DONE)
    local groupId = nil
    
    if ok then
        groupId = M._db:last_insert_rowid()
    end
    
    local err = not ok and last_error() or nil
    stmt:finalize()
    
    if ok then
        return true, groupId
    else
        return false, err
    end
end

function M.delete_group(groupId)
    if not M._db then return false, 'db not initialized' end
    if not groupId then return false, 'group id required' end
    
    local stmt = M._db:prepare('DELETE FROM bot_groups WHERE id = ?')
    if not stmt then return false, 'prepare failed' end
    
    stmt:bind_values(groupId)
    local rc = stmt:step()
    local ok = (rc == sqlite3.DONE)
    
    stmt:finalize()
    return ok, not ok and last_error() or nil
end

function M.update_group(groupId, name, description)
    if not M._db then return false, 'db not initialized' end
    if not groupId or not name then return false, 'group id and name required' end
    
    local stmt = M._db:prepare('UPDATE bot_groups SET name = ?, description = ?, updated_at = strftime(\'%s\',\'now\') WHERE id = ?')
    if not stmt then return false, 'prepare failed' end
    
    stmt:bind_values(name, description or '', groupId)
    local rc = stmt:step()
    local ok = (rc == sqlite3.DONE)
    
    stmt:finalize()
    return ok, not ok and last_error() or nil
end

function M.get_all_groups()
    if not M._db then return {} end
    return collect_rows('SELECT id, name, description, created_at, updated_at FROM bot_groups ORDER BY name', nil)
end

function M.add_bot_to_group(groupId, botName)
    if not M._db then return false, 'db not initialized' end
    if not groupId or not botName then return false, 'group id and bot name required' end
    
    local stmt = M._db:prepare('INSERT OR IGNORE INTO bot_group_members (group_id, bot_name) VALUES (?, ?)')
    if not stmt then return false, 'prepare failed' end
    
    stmt:bind_values(groupId, botName)
    local rc = stmt:step()
    local ok = (rc == sqlite3.DONE)
    
    stmt:finalize()
    return ok, not ok and last_error() or nil
end

function M.remove_bot_from_group(groupId, botName)
    if not M._db then return false, 'db not initialized' end
    if not groupId or not botName then return false, 'group id and bot name required' end
    
    local stmt = M._db:prepare('DELETE FROM bot_group_members WHERE group_id = ? AND bot_name = ?')
    if not stmt then return false, 'prepare failed' end
    
    stmt:bind_values(groupId, botName)
    local rc = stmt:step()
    local ok = (rc == sqlite3.DONE)
    
    stmt:finalize()
    return ok, not ok and last_error() or nil
end

function M.get_group_members(groupId)
    if not M._db then return {} end
    if not groupId then return {} end
    
    return collect_rows('SELECT bot_name, added_at FROM bot_group_members WHERE group_id = ? ORDER BY bot_name', function(s)
        s:bind_values(groupId)
    end)
end

function M.get_groups_with_members()
    if not M._db then return {} end
    
    local groups = M.get_all_groups()
    for _, group in ipairs(groups) do
        group.members = M.get_group_members(group.id)
    end
    
    return groups
end

return M
